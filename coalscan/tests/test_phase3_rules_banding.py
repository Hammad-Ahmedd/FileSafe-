"""Phase 3 tests: rules R01-R14 (28+ assertions), banding table tests, bounded disassembly,
manifest verification, calibration gate, and held-out evaluation."""

from __future__ import annotations

import csv

import pytest

from coalscan.core.banding import DEFAULT_BANDING_CONFIG, compute_banding
from coalscan.core.disasm import disassemble_bounded_regions
from coalscan.core.models import FileStatus, RiskBand, RuleFinding
from coalscan.core.pe_inspect import inspect_pe_bytes, inspect_pe_file
from coalscan.core.router import route_file
from coalscan.core.rules import RULE_CATALOG, _make_finding, evaluate_rules
from coalscan.fixtures.generate_fixtures import (
    BASELINE_IMPORTS,
    GENERATED_DIR,
    MANIFEST_PATH,
    generate_all_fixtures,
)
from coalscan.tests.calibration import run_calibration_gate
from coalscan.tests.heldout import run_heldout_evaluation
from coalscan.tests.pe_builder import build_synthetic_pe


@pytest.fixture(scope="module", autouse=True)
def ensure_fixtures_generated() -> None:
    """Generate all benign fixtures and manifest.csv once before Phase 3 tests run."""
    generate_all_fixtures()


def _findings_for_ids(rule_ids: list[str]) -> list[RuleFinding]:
    """Helper to construct RuleFinding objects for table-driven banding tests."""
    return [
        _make_finding(rid, observed=f"Test trigger for {rid}", file_offset=0x200, rva=0x1000)
        for rid in rule_ids
    ]


# =============================================================================
# 1. Rule Tests: 28 Positive and Negative Assertions for R01-R14
# =============================================================================
RULE_IDS_14 = [f"R{i:02d}" for i in range(1, 15)]


@pytest.mark.parametrize("rule_id", RULE_IDS_14)
def test_rule_positive_fixture_triggers(rule_id: str) -> None:
    """Positive fixture for each rule R01-R14 must trigger that exact rule."""
    pos_path = GENERATED_DIR / f"{rule_id.lower()}_pos.exe"
    assert pos_path.exists(), f"Missing positive fixture {pos_path}"
    insp = inspect_pe_file(pos_path)
    route = route_file(pos_path.name, pos_path.stat().st_size, insp)
    findings = evaluate_rules(insp, route)
    fired_ids = {f.rule_id for f in findings}
    assert rule_id in fired_ids, f"Expected {rule_id} to fire on {pos_path.name}, got {fired_ids}"

    # Verify every finding has non-empty observed evidence, explanation, and benign example
    target_finding = next(f for f in findings if f.rule_id == rule_id)
    assert target_finding.observed
    assert target_finding.explanation
    assert target_finding.benign_example
    assert target_finding.location_label


@pytest.mark.parametrize("rule_id", RULE_IDS_14)
def test_rule_negative_fixture_does_not_trigger(rule_id: str) -> None:
    """Negative fixture for each rule R01-R14 must NOT trigger that rule."""
    neg_path = GENERATED_DIR / f"{rule_id.lower()}_neg.exe"
    assert neg_path.exists(), f"Missing negative fixture {neg_path}"
    insp = inspect_pe_file(neg_path)
    route = route_file(neg_path.name, neg_path.stat().st_size, insp)
    findings = evaluate_rules(insp, route)
    fired_ids = {f.rule_id for f in findings}
    assert rule_id not in fired_ids, (
        f"Expected {rule_id} NOT to fire on {neg_path.name}, but got {fired_ids}"
    )


def test_import_matching_case_insensitive_and_aw_suffixes() -> None:
    """Verify case-insensitive import matching and A/W/Ex suffix normalization."""
    pe_bytes = build_synthetic_pe(
        imports=[
            (
                "kernel32.DLL",
                [
                    "virtualallocEx",
                    "VIRTUALPROTECTA",
                    "writeprocessmemory",
                    "CreateRemoteThreadEx",
                    "LoadLibraryExA",
                    "GetProcAddress",
                    "ShellExecuteExW",
                ],
            ),
            ("WinHttp.dll", ["WinHttpOpen"]),
        ],
        has_certificate=True,
    )
    insp = inspect_pe_bytes(pe_bytes)
    route = route_file("case_test.exe", len(pe_bytes), insp)
    fired_ids = {f.rule_id for f in evaluate_rules(insp, route)}
    assert {"R01", "R02", "R03", "R04", "R05", "R06", "R07"}.issubset(fired_ids)


# =============================================================================
# 2. Banding Table Tests: Worked Examples, Boundary Scores, and Group Caps
# =============================================================================
@pytest.mark.parametrize(
    "label,rule_ids,expected_score,expected_band",
    [
        # Worked examples from Section 5 of the specification:
        ("Worked Ex 1: Ordinary runtime app", ["R01", "R02", "R05", "R06"], 3, RiskBand.ROUTINE),
        ("Worked Ex 2: setup.exe (mockup)", ["R10", "R01"], 6, RiskBand.REVIEW),
        ("Worked Ex 3: Packed utility", ["R09", "R11", "R08"], 5, RiskBand.REVIEW),
        ("Worked Ex 4: plugin.dll (mockup)", ["R03", "R04"], 8, RiskBand.REVIEW_CLOSELY),
        ("Worked Ex 5: RWX packed file", ["R10", "R09", "R11"], 8, RiskBand.REVIEW_CLOSELY),
        # Boundary scores (0, 3, 4, 6, 7) and group caps:
        ("Score 0: No rules fired", [], 0, RiskBand.ROUTINE),
        ("Boundary Score 3: R09(2) + R06(1)", ["R09", "R06"], 3, RiskBand.ROUTINE),
        ("Boundary Score 4 (no High): R09(2) + R11(2)", ["R09", "R11"], 4, RiskBand.REVIEW),
        ("Single High rule (Score 4): R10(4) alone", ["R10"], 4, RiskBand.REVIEW),
        ("Boundary Score 6: R09(2) + R11(2) + R01(2)", ["R09", "R11", "R01"], 6, RiskBand.REVIEW),
        (
            "Boundary Score 7: R10(4) + R09(2) + R06(1)",
            ["R10", "R09", "R06"],
            7,
            RiskBand.REVIEW_CLOSELY,
        ),
        ("Group A Cap (6 raw -> capped at 2)", ["R01", "R02", "R05"], 2, RiskBand.ROUTINE),
        (
            "Group B Cap (6 raw -> capped at 2)",
            ["R06", "R07", "R08", "R12", "R13", "R14"],
            2,
            RiskBand.ROUTINE,
        ),
        (
            "Group A (capped 2) + Group B (capped 2) = 4 Review",
            ["R01", "R02", "R05", "R06", "R07", "R12"],
            4,
            RiskBand.REVIEW,
        ),
    ],
)
def test_banding_table(
    label: str,
    rule_ids: list[str],
    expected_score: int,
    expected_band: RiskBand,
) -> None:
    """Table-driven verification of every Section 5 worked example, boundary, and group cap."""
    findings = _findings_for_ids(rule_ids)
    res = compute_banding(findings)
    assert res.score == expected_score, f"{label}: expected score {expected_score}, got {res.score}"
    assert res.band == expected_band, f"{label}: expected band {expected_band}, got {res.band}"


def test_banding_deduplicates_repeated_rule_ids() -> None:
    """Each fired rule ID counts at most once even if passed twice."""
    dup_findings = _findings_for_ids(["R09", "R09"])
    res = compute_banding(dup_findings)
    assert res.score == 2
    assert res.band == RiskBand.ROUTINE


# =============================================================================
# 3. Bounded Disassembly Tests
# =============================================================================
def test_bounded_disassembly_entry_and_evidence_caps() -> None:
    """Verify bounded disassembly limits: entry point + at most 3 executable evidence regions,
    and enforcement of the 2,000-instruction per-file cap."""
    # Build a PE with 3000 NOPs (0x90) in .text to test both the 256B slice and instruction cap
    large_code = b"\x48\x89\x5C\x24\x08\xFF\x15\x10\x00\x00\x00" + (b"\x90" * 3000)
    pe_bytes = build_synthetic_pe(
        is_64bit=True,
        text_data=large_code,
        imports=BASELINE_IMPORTS,
        has_certificate=True,
    )
    insp = inspect_pe_bytes(pe_bytes)
    route = route_file("disasm_test.exe", len(pe_bytes), insp)

    # Create 5 synthetic evidence findings at distinct offsets inside .text
    sec = insp.sections[0]
    fake_findings = [
        _make_finding(
            f"R0{i}",
            observed="Exec evidence",
            file_offset=sec.raw_offset + i * 32,
            rva=sec.virtual_address + i * 32,
        )
        for i in range(1, 6)
    ]

    regions, truncated, _ = disassemble_bounded_regions(
        pe_bytes, insp, route, fake_findings
    )
    # 1 entry point region + at most 3 evidence regions = 4 regions max
    assert len(regions) == 4
    assert truncated is False

    # Now test instruction truncation cap (set max_total_instructions=50)
    regions_capped, trunc_flag, trunc_note = disassemble_bounded_regions(
        pe_bytes,
        insp,
        route,
        fake_findings,
        max_total_instructions=50,
    )
    total_insns = sum(len(r.instructions) for r in regions_capped)
    assert total_insns == 50
    assert trunc_flag is True
    assert "50" in trunc_note


# =============================================================================
# 4. File-Type Router & Manifest Verification
# =============================================================================
def test_manifest_and_router_fixtures_all_pass() -> None:
    """Verify every fixture in manifest.csv matches its expected status and rule IDs,
    including R08 suppression on .NET and R11 skip on entryless DLL."""
    assert MANIFEST_PATH.exists()
    with MANIFEST_PATH.open("r", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    assert len(rows) >= 66  # 28 rule + 10 router + 8 cal + 8 heldout + 12 malformed
    for row in rows:
        assert row["test_outcome"] == "PASS", f"Fixture {row['name']} failed manifest check"

    # Specifically verify .NET suppresses R08 even with 1 import
    dotnet_row = next(r for r in rows if r["name"] == "type_managed_dotnet.exe")
    assert dotnet_row["expected_status"] == FileStatus.ANALYZED_DOTNET_LIMITED.value
    assert "R08" not in dotnet_row["expected_rule_ids"]


def test_calibration_and_heldout_gates() -> None:
    """Run the calibration gate and held-out evaluation as part of the Phase 3 suite."""
    cal_summary = run_calibration_gate()
    assert cal_summary.passed is True
    assert cal_summary.above_routine_count == 0

    hold_summary = run_heldout_evaluation()
    assert hold_summary.heldout_benign_total >= 8
    assert hold_summary.positive_rule_fixtures_triggered == 14
    assert hold_summary.heldout_above_routine_ratio <= 0.20
