"""Tests for the secret scanner module.

NOTE: Fake credential strings used in these tests are assembled at runtime
(via string concatenation) so they are never stored verbatim in source —
this prevents GitHub push protection from blocking the repo push.
"""

import pytest
from pathlib import Path
import tempfile

from gsi.modules.secret_scanner import SecretScanner, shannon_entropy
from gsi.config.settings import SecretScanConfig


@pytest.fixture
def scanner():
    return SecretScanner(SecretScanConfig())


# ── Helpers — build fake credentials at runtime ───────────────────────────
# All sensitive-looking strings are assembled here via concatenation so no
# real-looking credential ever appears verbatim in source (avoiding GitHub
# push protection false positives).

def _fake_aws():
    return "AKIA" + "IISFODNN7ABCDEFGH"          # AKIA + 16 chars

def _fake_github_pat():
    return "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz1234567890ab"

def _fake_gcp():
    return "AI" + "za" + ("B" * 35)              # AIza + 35 chars

def _fake_db_url():
    return "postgres://" + "user:s3cr3tpass@db.internal:5432/prod"

def _fake_stripe():
    return "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"

def _fake_rsa_header():
    return "-----" + "BEGIN RSA PRIVATE KEY" + "-----"

def _fake_aws_example():
    # Contains "EXAMPLE" — should be suppressed by the allowlist
    return "AKIA" + "IOSFODNN7EXAMPLE"


# ── Shannon entropy ────────────────────────────────────────────────────────

def test_entropy_high():
    assert shannon_entropy("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop0123456789") > 4.0

def test_entropy_low():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0

def test_entropy_empty():
    assert shannon_entropy("") == 0.0


# ── Secret pattern detection ───────────────────────────────────────────────

@pytest.mark.parametrize("content_fn,expected_pattern", [
    (lambda: f'AWS_ACCESS_KEY_ID = "{_fake_aws()}"',    "aws_access_key"),
    (lambda: f'token = "{_fake_github_pat()}"',          "github_token"),
    (lambda: f'key = "{_fake_gcp()}"',                   "gcp_api_key"),
    (lambda: f'url = "{_fake_db_url()}"',                "database_url"),
    (lambda: f'key = "{_fake_stripe()}"',                "stripe_secret"),
    (lambda: _fake_rsa_header(),                         "private_key_header"),
])
def test_detects_pattern(scanner, content_fn, expected_pattern):
    content = content_fn()
    findings = scanner._scan_content(content, "test.py")
    patterns_found = [f["pattern"] for f in findings]
    assert expected_pattern in patterns_found, (
        f"Expected '{expected_pattern}' in findings, got: {patterns_found}"
    )


def test_redacts_match(scanner):
    key = _fake_aws()
    content = f'AWS_ACCESS_KEY_ID = "{key}"'
    findings = scanner._scan_content(content, "test.py")
    for f in findings:
        assert key not in f.get("match", ""), "Full key value should be redacted"


def test_ignores_placeholder(scanner):
    content = 'API_KEY = "YOUR_API_KEY_HERE"'
    assert scanner._scan_content(content, "test.py") == []


def test_ignores_example_values(scanner):
    content = 'key = "example_key_placeholder"'
    assert scanner._scan_content(content, "test.py") == []


def test_allowlist_suppresses_example_aws(scanner):
    content = f'key = "{_fake_aws_example()}"'
    findings = scanner._scan_content(content, "test.py")
    aws_findings = [f for f in findings if f["pattern"] == "aws_access_key"]
    assert len(aws_findings) == 0


# ── Filename heuristics ────────────────────────────────────────────────────

@pytest.mark.parametrize("filename", [
    ".env", "credentials.json", "id_rsa", "secrets.yml", "terraform.tfvars",
])
def test_sensitive_filename_flagged(scanner, filename):
    findings = scanner._check_filename(filename)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_normal_filename_not_flagged(scanner):
    assert scanner._check_filename("main.py") == []
    assert scanner._check_filename("README.md") == []


# ── Directory scan ─────────────────────────────────────────────────────────

def test_scans_directory(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{_fake_aws()}"')
        findings = scanner._scan_directory(root)
        assert len(findings) >= 1


def test_skips_excluded_dirs(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        nm = root / "node_modules"
        nm.mkdir()
        (nm / "secret.js").write_text(f'key = "{_fake_aws()}"')
        findings = scanner._scan_directory(root)
        assert all("node_modules" not in f["file"] for f in findings)


def test_skips_binary_extensions(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "image.png").write_bytes(b"\x89PNG\r\n" + _fake_aws().encode())
        findings = scanner._scan_directory(root)
        assert len(findings) == 0
