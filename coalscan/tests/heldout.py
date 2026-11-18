"""Held-out evaluation runner and test (Section 5 & Section 6).

Runs the frozen rules ONCE on the `heldout` benign set and on positive rule fixtures,
reporting counts and reasons without ever tuning weights or thresholds.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from coalscan.core.banding import DEFAULT_BANDING_CONFIG, compute_banding
from coalscan.core.models import RiskBand
from coalscan.core.pe_inspect import inspect_pe_file
from coalscan.core.router import route_file
from coalscan.core.rules import evaluate_rules
from coalscan.fixtures.generate_fixtures import (
    GENERATED_DIR,
    MANIFEST_PATH,
    generate_all_fixtures,
)


@dataclass(frozen=True)
class HeldoutFileReport:
    """Held-out evaluation record for a single file."""

    name: str
    fixture_set: str
    status: str
    score: int
    band: RiskBand
    fired_rules: list[str]
    breakdown: str
    reason_above_routine: str


@dataclass(frozen=True)
class HeldoutEvaluationSummary:
    """Descriptive summary of the frozen rule engine on the held-out set."""

    heldout_benign_total: int
    heldout_benign_routine: int
    heldout_benign_above_routine: int
    heldout_above_routine_ratio: float
    positive_rule_fixtures_total: int
    positive_rule_fixtures_triggered: int
    benign_reports: list[HeldoutFileReport]
    above_routine_explanations: list[str]


def run_heldout_evaluation(
    manifest_path: Path = MANIFEST_PATH,
    fixtures_dir: Path = GENERATED_DIR,
) -> HeldoutEvaluationSummary:
    """Run the frozen DEFAULT_BANDING_CONFIG once on held-out benign and positive fixtures."""
    assert DEFAULT_BANDING_CONFIG.calibrated_and_frozen is True, (
        "Rules and banding weights must be frozen before running held-out evaluation"
    )

    if not manifest_path.exists() or not fixtures_dir.exists():
        generate_all_fixtures(output_dir=fixtures_dir, manifest_path=manifest_path)

    with manifest_path.open("r", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    heldout_rows = [r for r in rows if r["set"] == "heldout"]
    pos_rule_rows = [
        r for r in rows if r["set"] == "rule" and r["name"].endswith("_pos.exe")
    ]

    benign_reports: list[HeldoutFileReport] = []
    above_explanations: list[str] = []

    for row in heldout_rows:
        fname = row["name"]
        fpath = fixtures_dir / fname
        insp = inspect_pe_file(fpath)
        route = route_file(fname, fpath.stat().st_size, insp)
        findings = evaluate_rules(insp, route, config=DEFAULT_BANDING_CONFIG)
        b_res = compute_banding(findings, config=DEFAULT_BANDING_CONFIG)
        fired_ids = [f.rule_id for f in findings]

        reason = ""
        if b_res.band != RiskBand.ROUTINE:
            details = "; ".join(f"{f.rule_id} ({f.observed})" for f in findings)
            reason = f"{fname} -> {b_res.band.value} ({b_res.breakdown}): {details}"
            above_explanations.append(reason)

        benign_reports.append(
            HeldoutFileReport(
                name=fname,
                fixture_set="heldout",
                status=route.status.value,
                score=b_res.score,
                band=b_res.band,
                fired_rules=fired_ids,
                breakdown=b_res.breakdown,
                reason_above_routine=reason,
            )
        )

    pos_triggered = 0
    for row in pos_rule_rows:
        fname = row["name"]
        fpath = fixtures_dir / fname
        insp = inspect_pe_file(fpath)
        route = route_file(fname, fpath.stat().st_size, insp)
        findings = evaluate_rules(insp, route, config=DEFAULT_BANDING_CONFIG)
        if findings:
            pos_triggered += 1

    total_benign = len(benign_reports)
    above_count = sum(1 for r in benign_reports if r.band != RiskBand.ROUTINE)
    routine_count = total_benign - above_count
    ratio = (above_count / total_benign) if total_benign > 0 else 0.0

    return HeldoutEvaluationSummary(
        heldout_benign_total=total_benign,
        heldout_benign_routine=routine_count,
        heldout_benign_above_routine=above_count,
        heldout_above_routine_ratio=ratio,
        positive_rule_fixtures_total=len(pos_rule_rows),
        positive_rule_fixtures_triggered=pos_triggered,
        benign_reports=benign_reports,
        above_routine_explanations=above_explanations,
    )


def test_heldout_evaluation_reports_without_tuning() -> None:
    """Verify held-out evaluation runs on >= 8 benign files, triggers all 14 positive fixtures,
    and stays within the proposed <= 20% above-Routine target."""
    summary = run_heldout_evaluation()
    assert summary.heldout_benign_total >= 8
    assert summary.positive_rule_fixtures_total == 14
    assert summary.positive_rule_fixtures_triggered == 14
    assert summary.heldout_above_routine_ratio <= 0.20


if __name__ == "__main__":
    res = run_heldout_evaluation()
    print(
        f"Held-out Benign Set: {res.heldout_benign_routine}/{res.heldout_benign_total} Routine, "
        f"{res.heldout_benign_above_routine} above Routine ({res.heldout_above_routine_ratio:.1%})"
    )
    for exp in res.above_routine_explanations:
        print(f"  Above Routine: {exp}")
