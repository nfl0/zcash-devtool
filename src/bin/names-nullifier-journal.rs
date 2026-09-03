//! Derive and benchmark the minimal public spend journal needed by arbitrary
//! exact-name resolution after the wallet has authenticated its compact scan.

use std::{
    collections::HashSet,
    fs::File,
    hint::black_box,
    io::{BufReader, Read, Write},
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use prost::Message;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zcash_client_backend::proto::compact_formats::CompactBlock;

#[derive(Debug, Parser)]
#[command(
    name = "names-nullifier-journal",
    about = "Build and benchmark a sparse Orchard-family nullifier journal"
)]
struct Cli {
    #[arg(long)]
    capture: PathBuf,

    /// Persist CNJ1 without overwriting an existing file.
    #[arg(long)]
    journal: PathBuf,

    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value_t = 250)]
    scan_iterations: u32,
}

#[derive(Debug)]
struct JournalBlock {
    height: u32,
    hash: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.scan_iterations > 0, "scan iterations must be positive");
    let build_started = Instant::now();
    let blocks = read_capture(&cli.capture)?;
    let build_seconds = build_started.elapsed().as_secs_f64();
    let nullifiers = blocks
        .iter()
        .flat_map(|block| block.nullifiers.iter().copied())
        .collect::<Vec<_>>();
    ensure!(
        !nullifiers.is_empty(),
        "capture contains no Orchard-family nullifiers"
    );
    let digest = write_journal(&cli.journal, &blocks)?;
    let journal_bytes = std::fs::metadata(&cli.journal)?.len();

    let absent = absent_target(&nullifiers);
    let direct_samples = (0..cli.scan_iterations)
        .map(|_| {
            let started = Instant::now();
            let found = nullifiers.iter().any(|candidate| candidate == &absent);
            black_box(found);
            started.elapsed().as_secs_f64() * 1_000.0
        })
        .collect::<Vec<_>>();
    let index_started = Instant::now();
    let index = nullifiers.iter().copied().collect::<HashSet<_>>();
    let index_build_ms = index_started.elapsed().as_secs_f64() * 1_000.0;
    let indexed_samples = (0..cli.scan_iterations)
        .map(|_| {
            let started = Instant::now();
            black_box(index.contains(&absent));
            started.elapsed().as_secs_f64() * 1_000.0
        })
        .collect::<Vec<_>>();

    let report = json!({
        "schema": "coppice-names-nullifier-journal-v1",
        "source": {
            "capture": cli.capture,
            "blocks": 250_000,
            "blocks_with_actions": blocks.len(),
            "nullifiers": nullifiers.len(),
            "raw_nullifier_bytes": nullifiers.len() * 32,
            "pool_model": "Orchard and Ironwood nullifiers share the public 32-byte representation relevant to bond-spend detection."
        },
        "journal": {
            "path": cli.journal,
            "format": "CNJ1 magic, followed by sparse u32-le height, 32-byte block hash, u32-le count, and ordered 32-byte nullifiers",
            "bytes": journal_bytes,
            "sha256": hex::encode(digest),
            "build_seconds_including_compact_decode": build_seconds
        },
        "lookup": {
            "absent_target_full_journal_scan_ms": distribution(&direct_samples),
            "hash_index_build_ms": index_build_ms,
            "hash_index_absent_lookup_ms": distribution(&indexed_samples),
            "iterations": cli.scan_iterations
        },
        "security_interpretation": [
            "A direct journal scan avoids trusting a secondary lookup index; the index may remain a disposable acceleration layer.",
            "The wallet must bind journal records atomically to its authenticated canonical scan and rewind them by block hash on reorg.",
            "A journal derived from an untrusted compact source is not made consensus-authentic merely by hashing the local file.",
            "Only nullifiers after a candidate head are needed to detect an unmatched spend; unrelated commitments and ciphertext are not Names currentness evidence."
        ]
    });
    let rendered = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &cli.output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create {} without overwriting", path.display()))?;
        file.write_all(rendered.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!("{rendered}");
    Ok(())
}

fn read_capture(path: &PathBuf) -> Result<Vec<JournalBlock>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open capture {}", path.display()))?,
    );
    let mut magic = [0u8; 5];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == b"CNHS\x01", "capture has wrong CNHS1 magic");
    let mut blocks = Vec::new();
    loop {
        let mut length = [0u8; 4];
        match reader.read(&mut length[..1])? {
            0 => break,
            1 => reader.read_exact(&mut length[1..])?,
            _ => unreachable!(),
        }
        let length = u32::from_le_bytes(length) as usize;
        ensure!(length <= 16 * 1024 * 1024, "capture frame exceeds 16 MiB");
        let mut encoded = vec![0u8; length];
        reader.read_exact(&mut encoded)?;
        let block = CompactBlock::decode(encoded.as_slice())?;
        let height = u32::try_from(block.height).context("block height exceeds u32")?;
        let hash = block
            .hash
            .as_slice()
            .try_into()
            .context("block hash length")?;
        let nullifiers = block
            .vtx
            .iter()
            .flat_map(|transaction| {
                transaction
                    .actions
                    .iter()
                    .chain(&transaction.ironwood_actions)
            })
            .map(|action| {
                action
                    .nullifier
                    .as_slice()
                    .try_into()
                    .context("nullifier length")
            })
            .collect::<Result<Vec<_>>>()?;
        if !nullifiers.is_empty() {
            blocks.push(JournalBlock {
                height,
                hash,
                nullifiers,
            });
        }
    }
    Ok(blocks)
}

fn write_journal(path: &PathBuf, blocks: &[JournalBlock]) -> Result<[u8; 32]> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {} without overwriting", path.display()))?;
    let mut digest = Sha256::new();
    let mut write = |bytes: &[u8]| -> Result<()> {
        file.write_all(bytes)?;
        digest.update(bytes);
        Ok(())
    };
    write(b"CNJ\x01")?;
    for block in blocks {
        write(&block.height.to_le_bytes())?;
        write(&block.hash)?;
        write(&u32::try_from(block.nullifiers.len())?.to_le_bytes())?;
        for nullifier in &block.nullifiers {
            write(nullifier)?;
        }
    }
    file.sync_all()?;
    Ok(digest.finalize().into())
}

fn absent_target(nullifiers: &[[u8; 32]]) -> [u8; 32] {
    for byte in 0..=u8::MAX {
        let candidate = [byte; 32];
        if !nullifiers.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("256 synthetic targets all appeared as real nullifiers")
}

fn distribution(values: &[f64]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / sorted.len() as f64;
    json!({
        "min": sorted[0],
        "p50": quantile(&sorted, 0.50),
        "p95": quantile(&sorted, 0.95),
        "p99": quantile(&sorted, 0.99),
        "max": sorted[sorted.len() - 1],
        "mean": mean,
        "standard_deviation": variance.sqrt()
    })
}

fn quantile(sorted: &[f64], probability: f64) -> f64 {
    let index = (((sorted.len() - 1) as f64 * probability).round() as usize).min(sorted.len() - 1);
    sorted[index]
}
