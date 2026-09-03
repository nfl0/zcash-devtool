#!/usr/bin/env python3
"""Render the phase-two Coppice Names speed model as a standalone HTML report."""

from __future__ import annotations

import argparse
import html
import json
import math
from pathlib import Path


COLORS = ["#17c88b", "#a16eff", "#ffb547", "#ff6b7a", "#4da3ff"]


def esc(value: object) -> str:
    return html.escape(str(value))


def duration(seconds: float) -> str:
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.1f} us"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 120:
        return f"{seconds:.1f} s"
    return f"{seconds / 60:.1f} min"


def bytes_label(value: float) -> str:
    if value >= 1e9:
        return f"{value / 1e9:.1f} GB"
    if value >= 1e6:
        return f"{value / 1e6:.1f} MB"
    return f"{value / 1e3:.1f} KB"


def bar_chart(title: str, rows: list[tuple[str, float, str]], unit: str, log: bool = False) -> str:
    width, height = 900, 90 + len(rows) * 56
    left, right, top = 260, 90, 50
    plot = width - left - right
    positive = [value for _, value, _ in rows if value > 0]
    maximum = max(positive) if positive else 1.0
    minimum = min(positive) if positive else 1.0

    def scaled(value: float) -> float:
        if value <= 0:
            return 0.0
        if not log or maximum == minimum:
            return plot * value / maximum
        lower = math.log10(minimum) - 0.35
        return plot * (math.log10(value) - lower) / (math.log10(maximum) - lower)

    marks = []
    for index, (label, value, shown) in enumerate(rows):
        y = top + index * 56
        bar_width = max(2 if value > 0 else 0, scaled(value))
        marks.append(
            f'<text x="{left - 12}" y="{y + 20}" text-anchor="end">{esc(label)}</text>'
            f'<rect x="{left}" y="{y}" width="{bar_width:.2f}" height="28" rx="3" fill="{COLORS[index % len(COLORS)]}"/>'
            f'<text x="{min(width - 4, left + bar_width + 8):.2f}" y="{y + 20}" class="value">{esc(shown)}</text>'
        )
    return (
        f'<section><h2>{esc(title)}</h2><svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{esc(title)}, {esc(unit)}"><line x1="{left}" y1="35" x2="{left}" y2="{height - 20}"/>'
        + "".join(marks)
        + f'<text x="{left}" y="{height - 2}" class="axis">{esc(unit)}{"; logarithmic width" if log else ""}</text></svg></section>'
    )


def lookup_chart(lookup: dict) -> str:
    width, height = 900, 330
    left, right, top, bottom = 82, 24, 40, 62
    plot_w, plot_h = width - left - right, height - top - bottom
    keys = ["p05", "p50", "p95"]
    series = [
        ("Local compact cache", "local_full_compact_cache_seconds", COLORS[0]),
        ("Sparse scheduled refetch", "sparse_window_refetch_seconds", COLORS[1]),
    ]
    maximum = max(lookup[key][field] for key in keys for _, field, _ in series)
    marks = []
    group = plot_w / len(keys)
    bar_w = 72
    for group_index, key in enumerate(keys):
        center = left + group * (group_index + 0.5)
        marks.append(f'<text x="{center:.1f}" y="{height - 28}" text-anchor="middle">{key.upper()}</text>')
        for series_index, (_, field, color) in enumerate(series):
            value = lookup[key][field]
            bar_h = plot_h * value / maximum
            x = center + (series_index - 1) * bar_w
            y = top + plot_h - bar_h
            marks.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 8}" height="{bar_h:.1f}" fill="{color}" rx="3"/>'
                f'<text x="{x + (bar_w - 8) / 2:.1f}" y="{max(top + 12, y - 7):.1f}" text-anchor="middle" class="value">{duration(value)}</text>'
            )
    ticks = []
    for tick in range(0, 5):
        value = maximum * tick / 4
        y = top + plot_h - plot_h * tick / 4
        ticks.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" class="grid"/><text x="{left-9}" y="{y+4:.1f}" text-anchor="end">{value:.0f}s</text>')
    legend = "".join(
        f'<rect x="{left + i*230}" y="8" width="14" height="14" fill="{color}"/><text x="{left + 20 + i*230}" y="20">{esc(label)}</text>'
        for i, (label, _, color) in enumerate(series)
    )
    return f'<section><h2>Arbitrary-name lookup: offset distribution</h2><svg viewBox="0 0 {width} {height}" role="img" aria-label="Lookup latency p05 p50 p95">{legend}{"".join(ticks)}{"".join(marks)}<text x="{width/2}" y="{height-4}" text-anchor="middle" class="axis">Name schedule offset across the measured six-month history</text></svg></section>'


def line_chart(adoption: list[dict]) -> str:
    width, height = 900, 330
    left, right, top, bottom = 84, 30, 35, 64
    plot_w, plot_h = width - left - right, height - top - bottom
    maximum_x = max(row["names_transactions_per_day"] for row in adoption)
    maximum_y = max(row["cold_stream_seconds_at_median_throughput"] for row in adoption)
    points = []
    labels = []
    for row in adoption:
        x = left + plot_w * row["names_transactions_per_day"] / maximum_x
        y = top + plot_h * (1 - row["cold_stream_seconds_at_median_throughput"] / maximum_y)
        points.append(f"{x:.1f},{y:.1f}")
        labels.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6"/><text x="{x:.1f}" y="{y-12:.1f}" text-anchor="middle" class="value">{duration(row["cold_stream_seconds_at_median_throughput"])}</text><text x="{x:.1f}" y="{height-30}" text-anchor="middle">{row["names_transactions_per_day"]}</text>')
    return f'<section><h2>Cold compact-stream latency under modeled adoption</h2><svg viewBox="0 0 {width} {height}" role="img" aria-label="Cold compact stream latency by Names transactions per day"><line x1="{left}" y1="{top+plot_h}" x2="{width-right}" y2="{top+plot_h}"/><line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_h}"/><polyline points="{" ".join(points)}" fill="none" stroke="{COLORS[4]}" stroke-width="4"/>{"".join(labels)}<text x="{width/2}" y="{height-4}" text-anchor="middle" class="axis">Total Coppice Names transactions per 1,152-block day</text><text transform="translate(18 {height/2}) rotate(-90)" text-anchor="middle" class="axis">Seconds at measured median throughput</text></svg></section>'


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    model = json.loads(args.model.read_text(encoding="utf-8"))
    local = model["local_replay"]
    lookup = model["arbitrary_lookup"]["offset_distribution"]
    storage = model["storage"]
    attack = model["adversarial"]

    local_rows = [
        ("Current generic + exact", local["measured_seconds"]["current_generic_plus_exact"], duration(local["measured_seconds"]["current_generic_plus_exact"])),
        ("Referenced COMMIT", local["derived_route_policy_seconds"]["referenced_commit_exact_only"], duration(local["derived_route_policy_seconds"]["referenced_commit_exact_only"])),
        ("No carrier routes", local["derived_route_policy_seconds"]["no_carrier_routes"], duration(local["derived_route_policy_seconds"]["no_carrier_routes"])),
        ("Batch-end roots target", local["derived_design_targets_seconds"]["referenced_plus_batch_end_roots"], duration(local["derived_design_targets_seconds"]["referenced_plus_batch_end_roots"])),
        ("Wallet-owned tree target", local["derived_design_targets_seconds"]["referenced_plus_wallet_owned_tree"], duration(local["derived_design_targets_seconds"]["referenced_plus_wallet_owned_tree"])),
    ]
    storage_rows = [
        ("Six-month compact cache", storage["full_six_month_compact_cache_bytes"], bytes_label(storage["full_six_month_compact_cache_bytes"])),
        ("Sparse nullifier journal", storage["six_month_sparse_nullifier_journal_bytes"], bytes_label(storage["six_month_sparse_nullifier_journal_bytes"])),
        ("192-block COMMIT tail", storage["referenced_commit_ttl_tail_framed_bytes"], bytes_label(storage["referenced_commit_ttl_tail_framed_bytes"])),
    ]
    attack_rows = [
        ("Old generic route, six months", attack["old_continuous_generic_route"]["forced_full_transaction_gigabytes"], f'{attack["old_continuous_generic_route"]["forced_full_transaction_gigabytes"]:.1f} GB'),
        ("Referenced design, unrelated generic", 0, "0 B"),
        ("Referenced design, one attacked name/day", attack["referenced_commit_design"]["one_daily_window_candidates"] * 56204 / 1e9, bytes_label(attack["referenced_commit_design"]["one_daily_window_candidates"] * 56204)),
    ]

    findings = "".join(f"<li>{esc(item)}</li>" for item in model["design_findings"])
    limits = "".join(f"<li>{esc(item)}</li>" for item in model["limits"])
    document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Coppice Names speed and adversarial analysis</title>
<style>
:root {{ color-scheme: dark; --bg:#0d1110; --surface:#151b19; --text:#edf5f1; --muted:#9caaa4; --line:#38433f; }}
* {{ box-sizing:border-box }} body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.55 system-ui,sans-serif }}
main {{ max-width:1080px; margin:auto; padding:40px 24px 80px }} h1 {{ font-size:clamp(30px,5vw,54px); line-height:1.05; margin:0 0 12px }}
h2 {{ font-size:21px; margin:0 0 16px }} p,li {{ color:var(--muted) }} .lead {{ font-size:18px; max-width:820px }}
.verdict {{ border-left:4px solid {COLORS[0]}; padding:2px 0 2px 18px; margin:28px 0 36px }} section {{ margin:34px 0; padding:24px; background:var(--surface); border:1px solid var(--line) }}
svg {{ width:100%; height:auto; overflow:visible }} svg text {{ fill:var(--text); font-size:13px }} svg line {{ stroke:var(--line) }} .grid {{ opacity:.55 }} .value {{ font-weight:700 }} .axis {{ fill:var(--muted); font-size:12px }}
.columns {{ display:grid; grid-template-columns:1fr 1fr; gap:18px }} .columns section {{ margin:0 }} code {{ color:#b5f7df }}
footer {{ margin-top:40px; border-top:1px solid var(--line); padding-top:20px }}
@media(max-width:760px) {{ main {{ padding:24px 14px 60px }} section {{ padding:16px }} .columns {{ grid-template-columns:1fr }} }}
</style></head><body><main>
<h1>Coppice Names speed, measured</h1>
<p class="lead">Six months and 250,000 mainnet blocks, treating Orchard and Ironwood as one Orchard-family workload. Direct measurements, arithmetic derivations, and unimplemented design targets are labeled separately.</p>
<div class="verdict"><strong>Decision:</strong> keep COMMIT → REVEAL, but let exact REVEAL discovery pull only its referenced historical COMMIT. Then remove Coppice's duplicate per-block commitment-tree root work from the light-wallet path. Do not add transaction grinding.</div>
{bar_chart("Six-month local replay", local_rows, "Wall-clock seconds; current measured, other values derived from isolated calibrations")}
{lookup_chart(lookup)}
{line_chart(model["adoption"])}
<div class="columns">
{bar_chart("Canonical evidence storage", storage_rows, "Bytes", log=True)}
{bar_chart("Forced full-transaction bytes", attack_rows, "Gigabytes; block-fill ceilings", log=True)}
</div>
<section><h2>What the adversarial model says</h2><p>The old continuously observed generic route permits a theoretical {attack["old_continuous_generic_route"]["six_month_candidates"]:,} forced fetches ({attack["old_continuous_generic_route"]["local_route_cpu_hours_p50"]:.1f} local CPU hours before network time). The referenced design makes unrelated generic-route fetches exactly zero. A targeted attacker can still fill one name's 24-block daily window: {attack["referenced_commit_design"]["one_daily_window_candidates"]:,} candidates and {duration(attack["referenced_commit_design"]["one_daily_window_route_plus_invalid_proof_seconds_p50"])} local route-plus-invalid-proof CPU. That attack is visible, bounded by the schedule and block space, and fee-paying.</p></section>
<section><h2>Architecture findings</h2><ol>{findings}</ol></section>
<section><h2>Evidence boundaries</h2><ul>{limits}</ul></section>
<footer><p>Reproduce the model with <code>scripts/names-speed-phase-two.py</code> and this report with <code>scripts/names-speed-report.py</code>. Raw JSON measurements and the CNHS1 capture remain alongside this file.</p></footer>
</main></body></html>'''
    args.output.write_text(document, encoding="utf-8")


if __name__ == "__main__":
    main()
