"""Tests for the code pattern scanner."""

import pytest
import tempfile
from pathlib import Path

from gsi.modules.pattern_scanner import PatternScanner
from gsi.config.settings import PatternScanConfig


@pytest.fixture
def scanner():
    return PatternScanner(PatternScanConfig())


def _scan_code(scanner, code: str, ext: str = ".py") -> list:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        f = root / f"test{ext}"
        f.write_text(code)
        return scanner._scan_file(f, root)


# ── SQL injection ──────────────────────────────────────────────────────────

def test_detects_sql_injection(scanner):
    code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
    findings = _scan_code(scanner, code)
    checks = [f["check"] for f in findings]
    assert "sql_injection_risk" in checks


# ── Command injection ──────────────────────────────────────────────────────

def test_detects_command_injection(scanner):
    code = 'import subprocess\nsubprocess.call("ls " + user_input, shell=True)'
    findings = _scan_code(scanner, code)
    checks = [f["check"] for f in findings]
    assert "command_injection_risk" in checks


# ── Weak crypto ────────────────────────────────────────────────────────────

def test_detects_md5(scanner):
    code = "import hashlib\nh = hashlib.md5(data)"
    findings = _scan_code(scanner, code)
    checks = [f["check"] for f in findings]
    assert "weak_crypto" in checks


def test_detects_sha1(scanner):
    code = "import hashlib\nh = hashlib.sha1(data)"
    findings = _scan_code(scanner, code)
    checks = [f["check"] for f in findings]
    assert "weak_crypto" in checks


# ── eval ───────────────────────────────────────────────────────────────────

def test_detects_eval(scanner):
    code = "result = eval(user_input)"
    findings = _scan_code(scanner, code)
    checks = [f["check"] for f in findings]
    assert "eval_usage" in checks


# ── Insecure deserialization ───────────────────────────────────────────────

def test_detects_unsafe_yaml_load(scanner):
    code = "import yaml\ndata = yaml.load(f)"
    findings = _scan_code(scanner, code)
    checks = [f["check"] for f in findings]
    assert "insecure_deserialization" in checks


def test_detects_pickle(scanner):
    code = "import pickle\nobj = pickle.loads(data)"
    findings = _scan_code(scanner, code)
    checks = [f["check"] for f in findings]
    assert "insecure_deserialization" in checks


# ── Extension filtering ────────────────────────────────────────────────────

def test_skips_wrong_extension(scanner):
    # SQL injection check only runs on certain extensions, not .md
    code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
    findings = _scan_code(scanner, code, ext=".md")
    sql_finds = [f for f in findings if f["check"] == "sql_injection_risk"]
    assert len(sql_finds) == 0


# ── Clean code ─────────────────────────────────────────────────────────────

def test_clean_code_no_findings(scanner):
    code = """
def add(a, b):
    return a + b

class MyClass:
    def __init__(self, name):
        self.name = name
"""
    findings = _scan_code(scanner, code)
    assert len(findings) == 0
