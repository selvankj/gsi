"""Tests for the risk scorer module."""

import pytest
from gsi.modules.risk_scorer import RiskScorer
from gsi.config.settings import RiskScoringConfig


@pytest.fixture
def scorer():
    return RiskScorer(RiskScoringConfig())


def _secret(severity="critical"):
    return {"type": "secret", "severity": severity, "description": "test"}

def _vuln(severity="critical"):
    return {"type": "vulnerability", "severity": severity, "package": "pkg", "version": "1.0"}


# ── Score basics ───────────────────────────────────────────────────────────

def test_clean_repo_low_score(scorer):
    result = scorer.score(
        meta={"private": True, "archived": False, "pushed_at": "2025-01-01T00:00:00Z"},
        findings={"secrets": [], "vulnerabilities": [], "patterns": []}
    )
    assert result["score"] < 15
    assert result["grade"] == "A"


def test_critical_secret_public_repo_high_score(scorer):
    result = scorer.score(
        meta={"private": False, "archived": False, "pushed_at": "2025-01-01T00:00:00Z"},
        findings={"secrets": [_secret("critical")], "vulnerabilities": [], "patterns": []}
    )
    assert result["score"] >= 30


def test_archived_repo_adds_points(scorer):
    clean = scorer.score(
        meta={"private": True, "archived": False, "pushed_at": "2025-01-01T00:00:00Z"},
        findings={}
    )
    archived = scorer.score(
        meta={"private": True, "archived": True, "pushed_at": "2025-01-01T00:00:00Z"},
        findings={}
    )
    assert archived["score"] > clean["score"]


def test_stale_repo_adds_points(scorer):
    fresh = scorer.score(
        meta={"private": True, "archived": False, "pushed_at": "2026-03-01T00:00:00Z"},
        findings={}
    )
    stale = scorer.score(
        meta={"private": True, "archived": False, "pushed_at": "2020-01-01T00:00:00Z"},
        findings={}
    )
    assert stale["score"] > fresh["score"]


def test_score_capped_at_100(scorer):
    findings = {
        "secrets":         [_secret("critical")] * 10,
        "vulnerabilities": [_vuln("critical")]   * 10,
        "patterns":        [{"severity": "critical"}] * 10,
    }
    result = scorer.score(
        meta={"private": False, "archived": True, "pushed_at": "2020-01-01T00:00:00Z"},
        findings=findings
    )
    assert result["score"] <= 100


# ── Grades ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected_grade", [
    (0,  "A"),
    (14, "A"),
    (15, "B"),
    (29, "B"),
    (30, "C"),
    (49, "C"),
    (50, "D"),
    (74, "D"),
    (75, "F"),
    (100,"F"),
])
def test_grade_boundaries(scorer, score, expected_grade):
    assert scorer._grade(score) == expected_grade


# ── Signal detail ──────────────────────────────────────────────────────────

def test_signals_list_populated(scorer):
    result = scorer.score(
        meta={"private": False, "archived": True, "pushed_at": "2020-01-01T00:00:00Z"},
        findings={"secrets": [_secret()], "vulnerabilities": [], "patterns": []}
    )
    keys = [s["key"] for s in result["signals"]]
    assert "is_archived" in keys
    assert "stale_repo" in keys
