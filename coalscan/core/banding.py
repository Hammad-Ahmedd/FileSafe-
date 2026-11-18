"""Transparent, deterministic risk-band calculation (Section 5).

Pure functions and centralized BandingConfig so calibration can inspect or freeze
weights, group caps, and band thresholds in one place.
Bands are triage aids (Routine, Review, Review closely), never malware verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from coalscan.core.limits import BANDING_VERSION, ENTROPY_THRESHOLD_BITS_PER_BYTE
from coalscan.core.models import RiskBand, RuleFinding, RuleSeverity


@dataclass(frozen=True)
class BandingConfig:
    """Centralized configuration for rule weights, group caps, and band thresholds.

    Frozen after the Week 4 calibration gate.
    """

    version: str = BANDING_VERSION
    low_points: int = 1
    medium_points: int = 2
    high_points: int = 4

    group_a_rules: frozenset[str] = field(
        default_factory=lambda: frozenset({"R01", "R02", "R05"})
    )
    group_b_rules: frozenset[str] = field(
        default_factory=lambda: frozenset({"R06", "R07", "R08", "R12", "R13", "R14"})
    )
    high_severity_rules: frozenset[str] = field(
        default_factory=lambda: frozenset({"R03", "R04", "R10"})
    )

    group_a_cap: int = 2
    group_b_cap: int = 2

    routine_max_score: int = 3
    review_max_score: int = 6
    review_closely_min_score: int = 7

    entropy_threshold: float = ENTROPY_THRESHOLD_BITS_PER_BYTE
    calibrated_and_frozen: bool = True


DEFAULT_BANDING_CONFIG: Final[BandingConfig] = BandingConfig()


@dataclass(frozen=True)
class BandingResult:
    """Computed score, triage band, and human-readable breakdown for a set of findings."""

    score: int
    band: RiskBand
    group_a_raw: int
    group_a_applied: int
    group_b_raw: int
    group_b_applied: int
    uncapped_points: int
    has_high_rule: bool
    breakdown: str


def compute_banding(
    findings: list[RuleFinding],
    config: BandingConfig = DEFAULT_BANDING_CONFIG,
) -> BandingResult:
    """Compute the capped triage score and RiskBand from a list of RuleFindings.

    Rules of the transparent banding algorithm (Section 5):
    - Each rule ID counts at most once (deduplicated by rule_id preserving order).
    - Group A (R01, R02, R05) adds at most `config.group_a_cap` (2) points combined.
    - Group B (R06, R07, R08, R12, R13, R14) adds at most `config.group_b_cap` (2) points combined.
    - All other rules (R03, R04, R09, R10, R11) are uncapped.
    - Routine: score 0..3 and no High rule.
    - Review: score 4..6, or any single High rule (when score < 7).
    - Review closely: score 7 or more.
    """
    unique_by_id: dict[str, RuleFinding] = {}
    for f in findings:
        if f.rule_id not in unique_by_id:
            unique_by_id[f.rule_id] = f

    deduped = list(unique_by_id.values())

    group_a_findings: list[RuleFinding] = []
    group_b_findings: list[RuleFinding] = []
    uncapped_findings: list[RuleFinding] = []
    has_high = False

    for f in deduped:
        if f.severity == RuleSeverity.HIGH or f.rule_id in config.high_severity_rules:
            has_high = True
        if f.group == "A" or f.rule_id in config.group_a_rules:
            group_a_findings.append(f)
        elif f.group == "B" or f.rule_id in config.group_b_rules:
            group_b_findings.append(f)
        else:
            uncapped_findings.append(f)

    group_a_raw = sum(f.points for f in group_a_findings)
    group_a_applied = min(group_a_raw, config.group_a_cap)

    group_b_raw = sum(f.points for f in group_b_findings)
    group_b_applied = min(group_b_raw, config.group_b_cap)

    uncapped_points = sum(f.points for f in uncapped_findings)
    total_score = group_a_applied + group_b_applied + uncapped_points

    if total_score >= config.review_closely_min_score:
        band = RiskBand.REVIEW_CLOSELY
    elif total_score > config.routine_max_score or has_high:
        band = RiskBand.REVIEW
    else:
        band = RiskBand.ROUTINE

    # Build human-readable score breakdown
    if not deduped:
        breakdown = "score 0 (no rules fired)"
    else:
        parts: list[str] = []
        for f in uncapped_findings:
            parts.append(f"{f.rule_id}: {f.points}")
        if group_a_findings:
            if group_a_raw > config.group_a_cap:
                ids_str = ", ".join(f.rule_id for f in group_a_findings)
                parts.append(f"Group A ({ids_str} capped at {config.group_a_cap})")
            else:
                for f in group_a_findings:
                    parts.append(f"{f.rule_id}: {f.points}")
        if group_b_findings:
            if group_b_raw > config.group_b_cap:
                ids_str = ", ".join(f.rule_id for f in group_b_findings)
                parts.append(f"Group B ({ids_str} capped at {config.group_b_cap})")
            else:
                for f in group_b_findings:
                    parts.append(f"{f.rule_id}: {f.points}")
        breakdown = f"score {total_score} = " + " + ".join(parts)

    return BandingResult(
        score=total_score,
        band=band,
        group_a_raw=group_a_raw,
        group_a_applied=group_a_applied,
        group_b_raw=group_b_raw,
        group_b_applied=group_b_applied,
        uncapped_points=uncapped_points,
        has_high_rule=has_high,
        breakdown=breakdown,
    )
