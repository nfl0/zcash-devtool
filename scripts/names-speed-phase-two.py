#!/usr/bin/env python3
"""Build the Coppice Names phase-two speed and adversarial model.

The model deliberately labels direct measurements, arithmetic derivations, and
design targets separately. It consumes only checked-in benchmark schemas plus
the immutable CNHS1 capture; it never treats synthetic traffic as canonical
Zcash history.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from pathlib import Path


def load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def distribution(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)

    def quantile(q: float) -> float:
        position = q * (len(ordered) - 1)
        low = math.floor(position)
        high = math.ceil(position)
        if low == high:
            return ordered[low]
        weight = position - low
        return ordered[low] * (1.0 - weight) + ordered[high] * weight

    mean = sum(ordered) / len(ordered)
    variance = sum((value - mean) ** 2 for value in ordered) / len(ordered)
    return {
        "min": ordered[0],
        "p05": quantile(0.05),
        "p50": quantile(0.50),
        "p95": quantile(0.95),
        "max": ordered[-1],
        "mean": mean,
        "standard_deviation": math.sqrt(variance),
    }


def capture_frames(path: Path) -> list[bytes]:
    with path.open("rb") as handle:
        if handle.read(5) != b"CNHS\x01":
            raise ValueError("capture has wrong CNHS1 magic")
        frames = []
        while True:
            encoded_length = handle.read(4)
            if not encoded_length:
                return frames
            if len(encoded_length) != 4:
                raise ValueError("truncated CNHS1 frame length")
            length = struct.unpack("<I", encoded_length)[0]
            frame = handle.read(length)
            if len(frame) != length:
                raise ValueError("truncated CNHS1 frame")
            frames.append(frame)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--measurements", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.measurements.resolve()

    manifest = load(directory / "manifest.json")
    current = load(directory / "light-wallet-replay-optimized.json")
    referenced = load(directory / "light-wallet-replay-referenced.json")
    route_history = load(directory / "route-history.json")
    frontier = load(directory / "frontier-calibration-34560.json")
    nullifiers = load(directory / "nullifier-journal.json")
    routed = load(directory / "route-adversarial-calibration-v2.json")
    proofs = load(directory / "adversarial-calibration-v2.json")
    synthetic = load(directory / "synthetic-scenarios-current.json")

    source = current["source"]
    blocks = source["blocks"]
    actions = source["orchard_family_actions"]
    compact_bytes = source["compact_payload_bytes"]
    scheduled = synthetic["simulation"]["scheduled_window_statistics"]
    network_bps = synthetic["simulation"]["network_bytes_per_second"]
    request_ms = synthetic["simulation"]["median_request_overhead_milliseconds"]

    frames = capture_frames(directory / "compact-blocks.cnhs")
    ttl_frames = frames[-192:]
    ttl_payload_bytes = sum(len(frame) for frame in ttl_frames)
    ttl_framed_bytes = ttl_payload_bytes + 4 * len(ttl_frames) + 5

    frontier_measurement = frontier["measurements"]
    calibrated_blocks = frontier["source"]["blocks"]
    calibrated_actions = frontier["source"]["actions"]
    repeated_root_seconds = (
        frontier_measurement["per_block_root_incremental_seconds"]
        * blocks
        / calibrated_blocks
    )
    append_once_seconds = (
        frontier_measurement["append_and_root_once_at_end_seconds"]
        * actions
        / calibrated_actions
    )
    current_wall = current["timing_seconds"]["wall"]
    referenced_wall = referenced["timing_seconds"]["wall"]
    generic_route_seconds = route_history["timing_seconds"]["continuous_generic_route_incremental"]
    exact_route_seconds = route_history["timing_seconds"]["scheduled_exact_route_incremental"]
    referenced_composed_estimate = max(0.0, current_wall - generic_route_seconds)
    no_routes_wall = max(0.0, referenced_wall - exact_route_seconds)
    batch_root_target = max(0.0, referenced_wall - repeated_root_seconds)
    wallet_tree_target = max(0.0, batch_root_target - append_once_seconds)

    route_only_seconds = exact_route_seconds
    scheduled_action_distribution = scheduled["actions_across_all_name_offsets"]
    mean_scheduled_actions = scheduled_action_distribution["mean"]
    route_seconds_per_action = route_only_seconds / mean_scheduled_actions
    nullifier_scan_seconds = (
        nullifiers["lookup"]["absent_target_full_journal_scan_ms"]["p50"] / 1000.0
    )

    lookup = {}
    for quantile in ("p05", "p50", "p95"):
        route_cpu = route_seconds_per_action * scheduled_action_distribution[quantile]
        local = route_cpu + nullifier_scan_seconds
        remote = (
            scheduled["payload_bytes_across_all_name_offsets"][quantile] / network_bps
            + scheduled["requests_if_each_epoch_is_queried_separately"] * request_ms / 1000.0
        )
        lookup[quantile] = {
            "local_full_compact_cache_seconds": local,
            "sparse_window_refetch_seconds": local + remote,
        }

    days = blocks / 1152.0
    commit = routed["fixtures"]["generic_commit"]
    reveal = routed["fixtures"]["exact_reveal"]
    # Each rate is total Names transactions/day, split evenly between the two
    # transactions of registration. Sixty-four bytes/transaction conservatively
    # covers compact txid/index protobuf overhead not included in action bytes.
    compact_commit_bytes = commit["compact_action_bytes"] + 64
    compact_reveal_bytes = reveal["compact_action_bytes"] + 64
    adoption = []
    for rate in (0, 10, 100, 1000):
        transaction_count = rate * days
        added_bytes = transaction_count * (compact_commit_bytes + compact_reveal_bytes) / 2.0
        added_actions = transaction_count * (commit["compact_actions"] + reveal["compact_actions"]) / 2.0
        adoption.append({
            "names_transactions_per_day": rate,
            "modeled_transactions": transaction_count,
            "modeled_added_actions": added_actions,
            "modeled_added_compact_bytes": added_bytes,
            "cold_stream_seconds_at_median_throughput": (compact_bytes + added_bytes) / network_bps,
            "compact_storage_megabytes": (compact_bytes + added_bytes) / 1_000_000.0,
            "composition": "50% 3-action COMMIT and 50% 13-action REVEAL; REFRESH has the REVEAL shape",
        })

    max_block_bytes = 2_000_000
    commits_per_block = max_block_bytes // commit["serialized_transaction_bytes"]
    reveals_per_block = max_block_bytes // reveal["serialized_transaction_bytes"]
    generic_candidates = blocks * commits_per_block
    scheduled_blocks = route_history["workload"]["scheduled_blocks"]
    exact_candidates = scheduled_blocks * reveals_per_block
    generic_local_ms = routed["measurements"]["generic_commit_route_hit"]["total_local_ms"]["p50"]
    reveal_local_ms = routed["measurements"]["exact_name_reveal_route_hit"]["total_local_ms"]["p50"]
    invalid_proof_ms = proofs["measurements"]["invalid_reveal_proof"]["p50_milliseconds"]
    referenced_pair_bytes = commit["serialized_transaction_bytes"] + reveal["serialized_transaction_bytes"]

    adversarial = {
        "assumptions": {
            "maximum_serialized_block_bytes": max_block_bytes,
            "no_transaction_grinding": True,
            "consensus_transaction_verification_excluded": "light wallet consumes consensus-admitted transactions",
            "fee_interpretation": "ceilings assume the attacker pays Zcash fees and fills blocks with valid transaction shapes",
        },
        "old_continuous_generic_route": {
            "generic_candidates_per_block": commits_per_block,
            "six_month_candidates": generic_candidates,
            "forced_full_transaction_gigabytes": generic_candidates * commit["serialized_transaction_bytes"] / 1e9,
            "local_route_cpu_hours_p50": generic_candidates * generic_local_ms / 3_600_000.0,
        },
        "referenced_commit_design": {
            "unrelated_generic_full_transactions_fetched": 0,
            "exact_candidates_per_scheduled_block": reveals_per_block,
            "candidate_blocks_in_capture": scheduled_blocks,
            "six_month_exact_candidates": exact_candidates,
            "forced_reveal_plus_commit_gigabytes": exact_candidates * referenced_pair_bytes / 1e9,
            "local_route_plus_invalid_proof_hours_p50": exact_candidates * (reveal_local_ms + invalid_proof_ms) / 3_600_000.0,
            "one_daily_window_candidates": reveals_per_block * 24,
            "one_daily_window_route_plus_invalid_proof_seconds_p50": reveals_per_block * 24 * (reveal_local_ms + invalid_proof_ms) / 1000.0,
            "referenced_pair_serialized_bytes": referenced_pair_bytes,
            "reachability": "Each proof-costing candidate must hit the exact name route in its window and reference a live canonical generic-route COMMIT.",
        },
    }

    output = {
        "schema": "coppice-names-speed-phase-two-v2",
        "generated_from": {
            "capture_sha256": hashlib.sha256((directory / "compact-blocks.cnhs").read_bytes()).hexdigest(),
            "measurement_files": [
                "manifest.json",
                "synthetic-scenarios-current.json",
                "light-wallet-replay-optimized.json",
                "light-wallet-replay-referenced.json",
                "route-history.json",
                "frontier-calibration-34560.json",
                "nullifier-journal.json",
                "route-adversarial-calibration-v2.json",
                "adversarial-calibration-v2.json",
            ],
        },
        "source": {
            "blocks": blocks,
            "actions": actions,
            "compact_payload_bytes": compact_bytes,
            "median_modeled_network_bytes_per_second": network_bps,
            "median_modeled_request_overhead_milliseconds": request_ms,
            "pool_model": "Orchard and Ironwood are one Orchard-family compact workload for this study.",
        },
        "local_replay": {
            "measured_seconds": {
                "current_generic_plus_exact": current_wall,
                "referenced_commit_exact_only": referenced_wall,
            },
            "derived_route_policy_seconds": {
                "no_carrier_routes": no_routes_wall,
                "qualification": "No-carrier-routes is derived by subtracting the isolated exact-route scan from the measured referenced-COMMIT replay.",
            },
            "route_policy_cross_check": {
                "referenced_commit_composed_estimate_seconds": referenced_composed_estimate,
                "measured_minus_composed_seconds": referenced_wall - referenced_composed_estimate,
                "qualification": "Run-to-run cross-check only; the direct referenced-COMMIT replay is authoritative for the measured point.",
            },
            "derived_design_targets_seconds": {
                "referenced_plus_batch_end_roots": batch_root_target,
                "referenced_plus_wallet_owned_tree": wallet_tree_target,
            },
            "root_calibration": {
                "extrapolated_repeated_root_seconds": repeated_root_seconds,
                "extrapolated_append_plus_final_root_seconds": append_once_seconds,
                "qualification": "Derived by linear extrapolation from the 34,560-block real-capture calibration; not an implementation benchmark.",
            },
        },
        "arbitrary_lookup": {
            "offset_distribution": lookup,
            "route_only_cpu_seconds_at_mean_offset": route_only_seconds,
            "direct_full_nullifier_journal_scan_seconds_p50": nullifier_scan_seconds,
            "scheduled_requests": scheduled["requests_if_each_epoch_is_queried_separately"],
            "interpretation": "A local compact cache gives the fastest trustless arbitrary lookup. Nullifier journal plus disjoint refetch saves storage but request latency dominates. Both are derived from canonical wallet scan state; neither is authority.",
        },
        "storage": {
            "full_six_month_compact_cache_bytes": compact_bytes,
            "six_month_sparse_nullifier_journal_bytes": nullifiers["journal"]["bytes"],
            "referenced_commit_ttl_tail_payload_bytes": ttl_payload_bytes,
            "referenced_commit_ttl_tail_framed_bytes": ttl_framed_bytes,
            "ttl_blocks": 192,
        },
        "adoption": adoption,
        "adversarial": adversarial,
        "design_findings": [
            "Keep COMMIT and REVEAL; REVEAL already contains the bounded CommitRef needed for on-demand authentication.",
            "Stop continuous generic-rendezvous acquisition in exact resolvers. Fetch only a wallet-authored pending COMMIT or the historical COMMIT referenced by an exact-route REVEAL.",
            "Do not add transaction grinding. Zcash fees and block limits are the publication anti-spam boundary; cheap schedule, shape, reference, and lineage gates must precede Names proof verification.",
            "Eliminate the duplicate Core commitment tree from the light-wallet path. The wallet owns note-tree checkpoints and Names needs authenticated positions plus canonical nullifier currentness, not a second per-block root calculation.",
            "For fastest arbitrary lookup, retain the six-month compact cache. A 27.1 MB sparse nullifier journal plus scheduled refetch is the lower-storage mode, but median request overhead makes it much slower.",
        ],
        "limits": [
            "The mainnet capture contains no Coppice deployment; Names traffic is synthesized from measured compact and full transaction shapes.",
            "Batch-root and wallet-owned-tree values are design targets derived from a shorter real-capture calibration, not measured implementations.",
            "Network figures use a previously measured median throughput and request overhead; endpoint behavior will vary.",
            "The 2 MB adversarial block-fill calculation is a ceiling, not an expected workload or a claim about miner policy.",
        ],
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
