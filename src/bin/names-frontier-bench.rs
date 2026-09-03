//! Isolate the Orchard-family frontier cost paid by Core light-wallet replay.

use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use serde_json::json;
use zcash_client_backend::proto::compact_formats::CompactBlock;

#[derive(Debug, Parser)]
#[command(
    name = "names-frontier-bench",
    about = "Compare per-block and end-only Orchard frontier roots"
)]
struct Cli {
    #[arg(long)]
    capture: PathBuf,

    #[arg(long)]
    max_blocks: Option<usize>,

    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let blocks = read_capture(&cli.capture, cli.max_blocks)?;
    ensure!(!blocks.is_empty(), "capture contains no blocks");
    let (per_block_seconds, per_block_root, actions) = run(&blocks, true)?;
    let (end_only_seconds, end_only_root, end_actions) = run(&blocks, false)?;
    ensure!(
        actions == end_actions,
        "frontier passes saw different action counts"
    );
    ensure!(per_block_root == end_only_root, "frontier roots differ");
    let report = json!({
        "schema": "coppice-names-frontier-calibration-v1",
        "source": {
            "capture": cli.capture,
            "blocks": blocks.len(),
            "actions": actions,
            "pool_model": "Orchard-era compact commitments are treated as equivalent Ironwood commitments."
        },
        "measurements": {
            "append_and_root_every_block_seconds": per_block_seconds,
            "append_and_root_once_at_end_seconds": end_only_seconds,
            "per_block_root_incremental_seconds": per_block_seconds - end_only_seconds,
            "speed_ratio": per_block_seconds / end_only_seconds,
            "final_root_hex": hex::encode(per_block_root)
        },
        "interpretation": "Both passes append the same canonical commitments and produce the same final root. The delta isolates repeated root materialization plus loop timing; it does not authorize skipping consensus-required wallet tree maintenance."
    });
    let rendered = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &cli.output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create {} without overwriting", path.display()))?;
        use std::io::Write as _;
        file.write_all(rendered.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!("{rendered}");
    Ok(())
}

fn run(blocks: &[Vec<u8>], root_every_block: bool) -> Result<(f64, [u8; 32], u64)> {
    let started = Instant::now();
    let mut frontier = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut actions = 0u64;
    for encoded in blocks {
        let compact = CompactBlock::decode(encoded.as_slice())?;
        for transaction in &compact.vtx {
            for action in transaction
                .actions
                .iter()
                .chain(&transaction.ironwood_actions)
            {
                let bytes: [u8; 32] = action
                    .cmx
                    .as_slice()
                    .try_into()
                    .context("compact commitment has wrong length")?;
                let commitment =
                    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
                        .context("compact commitment is not canonical")?;
                frontier
                    .append(commitment)
                    .map_err(|_| anyhow::anyhow!("frontier append failed"))?;
                actions += 1;
            }
        }
        if root_every_block {
            std::hint::black_box(frontier.root());
        }
    }
    let root = frontier.root().to_bytes();
    Ok((started.elapsed().as_secs_f64(), root, actions))
}

fn read_capture(path: &PathBuf, max_blocks: Option<usize>) -> Result<Vec<Vec<u8>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open capture {}", path.display()))?,
    );
    let mut magic = [0u8; 5];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == b"CNHS\x01", "capture has wrong CNHS1 magic");
    let mut blocks = Vec::new();
    while max_blocks.is_none_or(|limit| blocks.len() < limit) {
        let mut length = [0u8; 4];
        match reader.read(&mut length[..1])? {
            0 => break,
            1 => reader.read_exact(&mut length[1..])?,
            _ => unreachable!(),
        }
        let length = u32::from_le_bytes(length) as usize;
        ensure!(length <= 16 * 1024 * 1024, "capture frame exceeds 16 MiB");
        let mut block = vec![0u8; length];
        reader.read_exact(&mut block)?;
        blocks.push(block);
    }
    Ok(blocks)
}
