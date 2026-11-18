"""Calibration gate runner and test (Section 5 & Section 6).

Runs the CALIBRATION benign set from `coalscan/fixtures/manifest.csv` and requires
every benign file in the calibration set to land in `Routine` (score 0-3, no High rule).
If any calibration file lands above Routine, reports the exact file, score, and
fired rules so weights/caps/thresholds can be adjusted in `core/banding.py` before freezing.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from coalscan.core.banding import BandingConfig, DEFAULT_BANDING_CONFIG, compute_banding
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
class CalibrationFileReport:
    """Calibration outcome for a single benign fixture."""

    name: str
    status: str
    score: int
    band: RiskBand
    fired_rules: list[str]
    breakdown: str
    passed: bool


@dataclass(frozen=True)
class CalibrationGateSummary:
    """Overall result of the Week 4 calibration gate."""

    total_files: int
    routine_count: int
    above_routine_count: int
    passed: bool
    reports: list[CalibrationFileReport]
    failure_reasons: list[str]


def run_calibration_gate(
    config: BandingConfig = DEFAULT_BANDING_CONFIG,
    manifest_path: Path = MANIFEST_PATH,
    fixtures_dir: Path = GENERATED_DIR,
) -> CalibrationGateSummary:
    """Evaluate all `set == 'calibration'` fixtures and verify every file lands in Routine."""
    if not manifest_path.exists() or not fixtures_dir.exists():
        generate_all_fixtures(output_dir=fixtures_dir, manifest_path=manifest_path)

    reports: list[CalibrationFileReport] = []
    failure_reasons: list[str] = []

    with manifest_path.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        cal_rows = [row for row in reader if row["set"] == "calibration"]

    for row in cal_rows:
        fname = row["name"]
        fpath = fixtures_dir / fname
        insp = inspect_pe_file(fpath)
        route = route_file(fname, fpath.stat().st_size, insp)
        findings = evaluate_rules(insp, route, config=config)
        b_res = compute_banding(findings, config=config)
        fired_ids = [f.rule_id for f in findings]
        passed = b_res.band == RiskBand.ROUTINE

        if not passed:
            failure_reasons.append(
                f"{fname} landed in '{b_res.band.value}' (score={b_res.score}, "
                f"fired_rules={fired_ids}, {b_res.breakdown})"
            )

        reports.append(
            CalibrationFileReport(
                name=fname,
                status=route.status.value,
                score=b_res.score,
                band=b_res.band,
                fired_rules=fired_ids,
                breakdown=b_res.breakdown,
                passed=passed,
            )
        )

    above_count = sum(1 for r in reports if not r.passed)
    return CalibrationGateSummary(
        total_files=len(reports),
        routine_count=len(reports) - above_count,
        above_routine_count=above_count,
        passed=(above_count == 0 and len(reports) >= 8),
        reports=reports,
        failure_reasons=failure_reasons,
    )


def test_calibration_gate_all_routine() -> None:
    """Pytest assertion for the calibration gate: >= 8 benign files, 100% Routine."""
    summary = run_calibration_gate()
    assert summary.total_files >= 8
    assert summary.passed is True, (
        "Calibration gate failed! Benign calibration files above Routine:\n"
        + "\n".join(summary.failure_reasons)
    )


if __name__ == "__main__":
    res = run_calibration_gate()
    print(f"Calibration Gate: {res.routine_count}/{res.total_files} Routine (PASS={res.passed})")
    for rep in res.reports:
        print(f"  - {rep.name}: {rep.band.value} ({rep.breakdown})")
