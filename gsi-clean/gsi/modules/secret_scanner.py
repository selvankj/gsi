"""
secret_scanner.py — Regex + Shannon entropy secret detection.

Fixes applied (CTO review):
  1. Entropy scanner now skips known false-positive patterns:
     - Minified JS / CSS (long lines, no whitespace ratio)
     - Lock file hashes (package-lock.json, yarn.lock, Cargo.lock, Pipfile.lock)
     - Base64-encoded image/font data (data: URI prefix)
     - UUIDs (fixed 8-4-4-4-12 hex format)
     - File hashes (hex strings of exactly 32/40/56/64 chars)
     - node_modules / vendor paths
     - Test fixture directories
  2. Entropy threshold raised from a naive 4.5 to 4.8 to cut noise.
  3. Minimum token length for entropy check raised to 20 chars.
  4. Added per-pattern context check so we only flag assignment-like context
     for generic high-entropy strings.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    pattern_name: str
    file: str
    line: int
    snippet: str           # redacted context line


# ---------------------------------------------------------------------------
# Regex patterns — ordered by specificity (most specific first)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[dict] = [
    # AWS
    {
        "name": "aws_access_key_id",
        "severity": "CRITICAL",
        "regex": re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
    },
    {
        "name": "aws_secret_access_key",
        "severity": "CRITICAL",
        "regex": re.compile(
            r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key"
            r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})"
        ),
    },
    # GCP
    {
        "name": "gcp_api_key",
        "severity": "HIGH",
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    },
    # GitHub tokens
    {
        "name": "github_pat_classic",
        "severity": "CRITICAL",
        "regex": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    },
    {
        "name": "github_pat_fine_grained",
        "severity": "CRITICAL",
        "regex": re.compile(r"github_pat_[0-9A-Za-z_]{82}"),
    },
    {
        "name": "github_app_token",
        "severity": "HIGH",
        "regex": re.compile(r"ghs_[0-9A-Za-z]{36}"),
    },
    # Stripe
    {
        "name": "stripe_secret_key",
        "severity": "CRITICAL",
        "regex": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    },
    {
        "name": "stripe_restricted_key",
        "severity": "HIGH",
        "regex": re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
    },
    # Slack
    {
        "name": "slack_bot_token",
        "severity": "HIGH",
        "regex": re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
    },
    {
        "name": "slack_webhook",
        "severity": "MEDIUM",
        "regex": re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
        ),
    },
    # Twilio
    {
        "name": "twilio_auth_token",
        "severity": "HIGH",
        "regex": re.compile(
            r"(?i)twilio[_\-\s]?auth[_\-\s]?token['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})"
        ),
    },
    # SendGrid
    {
        "name": "sendgrid_api_key",
        "severity": "HIGH",
        "regex": re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    },
    # NPM
    {
        "name": "npm_token",
        "severity": "HIGH",
        "regex": re.compile(r"npm_[A-Za-z0-9]{36}"),
    },
    # Private keys (PEM headers)
    {
        "name": "private_key_pem",
        "severity": "CRITICAL",
        "regex": re.compile(
            r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE KEY-----"
        ),
    },
    # JWT (only flag ones that look real — 3 base64 segments)
    {
        "name": "jwt_token",
        "severity": "HIGH",
        "regex": re.compile(
            r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"
        ),
    },
    # Database URLs with embedded credentials
    {
        "name": "database_url_with_creds",
        "severity": "CRITICAL",
        "regex": re.compile(
            r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]{3,}@[a-zA-Z0-9.\-]+"
        ),
    },
    # Generic hardcoded password assignment
    {
        "name": "hardcoded_password",
        "severity": "HIGH",
        "regex": re.compile(
            r"""(?i)(?:password|passwd|pwd)\s*=\s*['"][^'"]{6,}['"]"""
        ),
    },
    # Heroku API key
    {
        "name": "heroku_api_key",
        "severity": "HIGH",
        "regex": re.compile(
            r"(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key['\"]?\s*[:=]\s*['\"]?"
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        ),
    },
]


# ---------------------------------------------------------------------------
# Entropy false-positive filters
# ---------------------------------------------------------------------------

# Paths that are almost always false positives for entropy scanning
_FP_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"node_modules/"),
    re.compile(r"vendor/"),
    re.compile(r"\.min\.(js|css)$"),
    re.compile(r"package-lock\.json$"),
    re.compile(r"yarn\.lock$"),
    re.compile(r"Cargo\.lock$"),
    re.compile(r"Pipfile\.lock$"),
    re.compile(r"poetry\.lock$"),
    re.compile(r"composer\.lock$"),
    re.compile(r"tests?/fixtures?/"),
    re.compile(r"tests?/data/"),
    re.compile(r"testdata/"),
    re.compile(r"__snapshots__/"),
]

# Token patterns that look high-entropy but are not secrets
_FP_TOKEN_PATTERNS: list[re.Pattern] = [
    # Pure hex hashes (MD5=32, SHA1=40, SHA224=56, SHA256=64, SHA512=128)
    re.compile(r"^[0-9a-f]{32}$", re.I),
    re.compile(r"^[0-9a-f]{40}$", re.I),
    re.compile(r"^[0-9a-f]{56}$", re.I),
    re.compile(r"^[0-9a-f]{64}$", re.I),
    re.compile(r"^[0-9a-f]{128}$", re.I),
    # UUIDs
    re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
    ),
    # data: URI content (images, fonts)
    re.compile(r"^data:[a-z]+/[a-z0-9.+\-]+;base64,"),
    # Version strings (e.g. "1.2.3-alpha.4+build.5")
    re.compile(r"^\d+\.\d+[\.\d\-+a-z]*$", re.I),
]

# Characters used in base64url (common in non-secret contexts too)
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

# Entropy thresholds (raised from naive 4.5)
_ENTROPY_THRESHOLD = 4.8
_ENTROPY_MIN_LEN = 20
_ENTROPY_MAX_LEN = 200  # avoid scoring entire minified lines


def _shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits per character) of string s."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _is_fp_token(token: str) -> bool:
    """Return True if the token matches a known false-positive pattern."""
    for pat in _FP_TOKEN_PATTERNS:
        if pat.match(token):
            return True
    return False


def _is_fp_path(filepath: str) -> bool:
    """Return True if the file path is a known false-positive source."""
    norm = filepath.replace("\\", "/")
    return any(pat.search(norm) for pat in _FP_PATH_PATTERNS)


def _is_minified_line(line: str) -> bool:
    """Heuristic: a line is minified if it's very long with almost no whitespace."""
    if len(line) < 200:
        return False
    whitespace_ratio = line.count(" ") / len(line)
    return whitespace_ratio < 0.02


def _high_entropy_tokens(line: str) -> list[str]:
    """
    Extract tokens from a line that look like they could be secrets based
    on entropy alone, after applying all false-positive filters.
    """
    # Only consider tokens that look like they could be a credential value:
    # preceded by = : " or whitespace
    candidates = re.findall(
        r"""(?<=[=:\"'\s])([A-Za-z0-9+/=_\-]{%d,%d})"""
        % (_ENTROPY_MIN_LEN, _ENTROPY_MAX_LEN),
        line,
    )
    results = []
    for token in candidates:
        if _is_fp_token(token):
            continue
        # Must consist mostly of base64url chars (filters plain English words)
        if sum(1 for c in token if c in _B64_CHARS) / len(token) < 0.85:
            continue
        if _shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            results.append(token)
    return results


# ---------------------------------------------------------------------------
# File-type skip list (binary / generated files)
# ---------------------------------------------------------------------------

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".class",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".sqlite", ".db", ".bin",
}


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class SecretScanner:
    def __init__(self, ignore_rules: Optional[list] = None):
        """
        ignore_rules: list of compiled ignore rules from gsiignore.py
        """
        self._ignore_rules = ignore_rules or []

    def scan_file(self, filepath: str, root: str = "") -> list[SecretFinding]:
        path = Path(filepath)
        if path.suffix.lower() in _SKIP_EXTENSIONS:
            return []

        rel = os.path.relpath(filepath, root) if root else filepath

        # Skip known false-positive file paths entirely for entropy
        entropy_eligible = not _is_fp_path(rel)

        findings: list[SecretFinding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._is_ignored(rel, lineno):
                continue

            stripped = line.strip()

            # 1. Regex patterns
            for pat in SECRET_PATTERNS:
                if pat["regex"].search(line):
                    if self._is_ignored(rel, lineno, pat["name"]):
                        continue
                    findings.append(
                        SecretFinding(
                            severity=pat["severity"],
                            pattern_name=pat["name"],
                            file=rel,
                            line=lineno,
                            snippet=self._redact(line),
                        )
                    )

            # 2. Entropy-based detection (only on entropy-eligible files)
            if entropy_eligible and not _is_minified_line(stripped):
                for token in _high_entropy_tokens(stripped):
                    if self._is_ignored(rel, lineno, "high_entropy_string"):
                        continue
                    findings.append(
                        SecretFinding(
                            severity="HIGH",
                            pattern_name="high_entropy_string",
                            file=rel,
                            line=lineno,
                            snippet=self._redact(line),
                        )
                    )

        # Deduplicate: same file+line+pattern
        seen: set[tuple] = set()
        deduped = []
        for f in findings:
            key = (f.file, f.line, f.pattern_name)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def scan_directory(self, directory: str) -> list[SecretFinding]:
        all_findings: list[SecretFinding] = []
        root = directory
        for dirpath, dirnames, filenames in os.walk(directory):
            # Skip hidden dirs and known noise dirs
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".")
                and d not in {"node_modules", "vendor", "__pycache__", ".git", "dist", "build"}
            ]
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                all_findings.extend(self.scan_file(filepath, root=root))
        return all_findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_ignored(
        self, rel_path: str, lineno: int, pattern_name: str = ""
    ) -> bool:
        for rule in self._ignore_rules:
            if rule.matches(rel_path, lineno, pattern_name):
                return True
        return False

    @staticmethod
    def _redact(line: str) -> str:
        """Return a redacted version of the line for display."""
        # Replace any token longer than 8 chars that looks like a secret value
        redacted = re.sub(
            r"""([:=]["']?\s*)([A-Za-z0-9+/=_\-]{8,})""",
            lambda m: m.group(1) + m.group(2)[:4] + "****",
            line.strip(),
        )
        return redacted[:120]  # cap display length
