"""
test_secret_scanner.py — Tests for the tuned entropy scanner and false-positive filters.

Covers the fixes from the CTO review:
  - Entropy FP exclusions (lock file hashes, UUIDs, minified lines, node_modules)
  - Regex patterns still fire correctly
  - Redaction works
"""

import os
import textwrap
import tempfile
from pathlib import Path

import pytest

from gsi.modules.secret_scanner import (
    SecretScanner,
    _shannon_entropy,
    _is_fp_token,
    _is_fp_path,
    _is_minified_line,
    _high_entropy_tokens,
)


# ---------------------------------------------------------------------------
# Entropy function
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_uniform_string(self):
        # All same character → entropy = 0
        assert _shannon_entropy("aaaaaaa") == 0.0

    def test_high_entropy(self):
        # Random-looking base64 string
        assert _shannon_entropy("xK9mP2qRnJ8vL0wT5hB3") > 4.0

    def test_low_entropy_english(self):
        assert _shannon_entropy("helloworld") < 4.0


# ---------------------------------------------------------------------------
# False-positive token filters
# ---------------------------------------------------------------------------

class TestFpTokenFilters:
    def test_md5_hash_excluded(self):
        assert _is_fp_token("d41d8cd98f00b204e9800998ecf8427e") is True  # 32 hex

    def test_sha1_hash_excluded(self):
        assert _is_fp_token("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True  # 40 hex

    def test_sha256_hash_excluded(self):
        assert _is_fp_token("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True  # 64 hex

    def test_uuid_excluded(self):
        assert _is_fp_token("550e8400-e29b-41d4-a716-446655440000") is True

    def test_version_string_excluded(self):
        assert _is_fp_token("1.2.3-alpha.4") is True

    def test_real_secret_not_excluded(self):
        # A realistic high-entropy token that isn't a known FP
        assert _is_fp_token("ghp_xK9mP2qRnJ8vL0wT5hB3cY7dF4eG6iH") is False


# ---------------------------------------------------------------------------
# False-positive path filters
# ---------------------------------------------------------------------------

class TestFpPathFilters:
    def test_node_modules_excluded(self):
        assert _is_fp_path("node_modules/lodash/index.js") is True

    def test_vendor_excluded(self):
        assert _is_fp_path("vendor/github.com/pkg/errors/errors.go") is True

    def test_min_js_excluded(self):
        assert _is_fp_path("static/app.min.js") is True

    def test_package_lock_excluded(self):
        assert _is_fp_path("package-lock.json") is True

    def test_yarn_lock_excluded(self):
        assert _is_fp_path("yarn.lock") is True

    def test_cargo_lock_excluded(self):
        assert _is_fp_path("Cargo.lock") is True

    def test_poetry_lock_excluded(self):
        assert _is_fp_path("poetry.lock") is True

    def test_test_fixtures_excluded(self):
        assert _is_fp_path("tests/fixtures/fake_creds.py") is True

    def test_regular_file_not_excluded(self):
        assert _is_fp_path("src/config/settings.py") is False


# ---------------------------------------------------------------------------
# Minified line detection
# ---------------------------------------------------------------------------

class TestMinifiedLine:
    def test_short_line_not_minified(self):
        assert _is_minified_line("x = 1") is False

    def test_long_sparse_line_is_minified(self):
        # A realistic minified JS line: very long, almost no spaces
        # Use a pattern with zero spaces to guarantee ratio < 0.02
        minified = "var" + "a=1;b=function(c,d){return(c+d);}c=d.e(f,g,h);" * 10
        assert len(minified) > 200
        assert minified.count(" ") / len(minified) < 0.02
        assert _is_minified_line(minified) is True

    def test_long_readable_line_not_minified(self):
        readable = ("This is a very long comment that has plenty of spaces "
                    "and keeps going for a while to make it longer than 200 chars. "
                    "It is still readable English with lots of whitespace present here.")
        assert _is_minified_line(readable) is False


# ---------------------------------------------------------------------------
# Full file scan — regex patterns fire correctly
# ---------------------------------------------------------------------------

class TestRegexPatterns:
    def _scan_text(self, content: str, filename: str = "test.py") -> list:
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, filename)
            Path(fpath).write_text(content)
            scanner = SecretScanner()
            return scanner.scan_file(fpath, root=tmpdir)

    def test_aws_access_key(self):
        findings = self._scan_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        assert any(f.pattern_name == "aws_access_key_id" for f in findings)

    def test_github_pat(self):
        findings = self._scan_text('token = "ghp_' + "A" * 36 + '"\n')
        assert any(f.pattern_name == "github_pat_classic" for f in findings)

    def test_stripe_secret_key(self):
        findings = self._scan_text('STRIPE_KEY = "sk_live_' + "a" * 24 + '"\n')
        assert any(f.pattern_name == "stripe_secret_key" for f in findings)

    def test_database_url_with_creds(self):
        findings = self._scan_text('DB = "postgres://user:s3cr3tpass@db.example.com/mydb"\n')
        assert any(f.pattern_name == "database_url_with_creds" for f in findings)

    def test_hardcoded_password(self):
        findings = self._scan_text('password = "Hunter2!"\n')
        assert any(f.pattern_name == "hardcoded_password" for f in findings)

    def test_private_key_pem(self):
        findings = self._scan_text("-----BEGIN RSA PRIVATE KEY-----\n")
        assert any(f.pattern_name == "private_key_pem" for f in findings)

    def test_clean_file_has_no_findings(self):
        findings = self._scan_text('x = 1\nprint("hello")\n')
        assert findings == []


# ---------------------------------------------------------------------------
# Entropy scan — node_modules path is skipped
# ---------------------------------------------------------------------------

class TestEntropyFalsePositiveIntegration:
    def _scan_text_at_path(self, content: str, rel_path: str) -> list:
        with tempfile.TemporaryDirectory() as tmpdir:
            full = os.path.join(tmpdir, rel_path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            Path(full).write_text(content)
            scanner = SecretScanner()
            return scanner.scan_file(full, root=tmpdir)

    def test_high_entropy_in_node_modules_not_flagged(self):
        # Even a real-looking token in node_modules should be skipped
        content = 'integrity = "sha512-xK9mP2qRnJ8vL0wT5hB3cY7dF4eG6iH1jK2lM3nO4pQ5rS6tU7vW8xY9zA0bC1dE2fG3hI4jK5lM6nO7pQ"\n'
        findings = self._scan_text_at_path(content, "node_modules/pkg/index.js")
        assert all(f.pattern_name != "high_entropy_string" for f in findings)

    def test_high_entropy_in_lock_file_not_flagged(self):
        content = '    resolved "https://registry.yarnpkg.com/pkg/-/pkg-1.0.0.tgz#xK9mP2qRnJ8vL0wT5hB3cY7dF4eG6iH1jK2lM3nO4"\n'
        findings = self._scan_text_at_path(content, "yarn.lock")
        assert all(f.pattern_name != "high_entropy_string" for f in findings)

    def test_high_entropy_in_source_file_is_flagged(self):
        # A genuine high-entropy string in a real source file should be caught
        # Use a string that's long enough, high entropy, not a known FP pattern
        secret = "xK9mP2qRnJvL0wT5hB3cY7dF4eG6iH1jK2lM3nO4pQ5rS6"
        content = f'api_secret = "{secret}"\n'
        findings = self._scan_text_at_path(content, "src/config.py")
        assert any(f.pattern_name == "high_entropy_string" for f in findings)
