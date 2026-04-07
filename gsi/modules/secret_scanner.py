"""
Secret Scanner — detects API keys, tokens, passwords, private keys.

Detection methods:
  1. Regex patterns per credential type (high precision)
  2. Shannon entropy analysis for high-entropy strings (catches generics)
  3. Filename heuristics (.env, *_key.*, credentials.*)
"""

import re
import math
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional

from gsi.config.settings import SecretScanConfig

# ── Secret pattern library ────────────────────────────────────────────────────

SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID"
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "critical",
        "description": "AWS Secret Access Key"
    },
    "github_token": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
        "severity": "critical",
        "description": "GitHub Personal Access Token"
    },
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "description": "Google Cloud / GCP API Key"
    },
    "gcp_service_account": {
        "pattern": r'"type":\s*"service_account"',
        "severity": "critical",
        "description": "GCP Service Account JSON"
    },
    "azure_client_secret": {
        "pattern": r"(?i)azure.{0,30}['\"][0-9a-zA-Z\-_~.]{34,}['\"]",
        "severity": "high",
        "description": "Azure Client Secret"
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,34}",
        "severity": "high",
        "description": "Slack API Token"
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        "severity": "high",
        "description": "Slack Incoming Webhook"
    },
    "stripe_secret": {
        "pattern": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "description": "Stripe Secret Key"
    },
    "stripe_publishable": {
        "pattern": r"pk_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "medium",
        "description": "Stripe Publishable Key"
    },
    "twilio_sid": {
        "pattern": r"AC[0-9a-fA-F]{32}",
        "severity": "high",
        "description": "Twilio Account SID"
    },
    "twilio_token": {
        "pattern": r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",
        "severity": "high",
        "description": "Twilio Auth Token"
    },
    "sendgrid_key": {
        "pattern": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "severity": "high",
        "description": "SendGrid API Key"
    },
    "private_key_header": {
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY( BLOCK)?-----",
        "severity": "critical",
        "description": "Private Key (RSA/EC/SSH)"
    },
    "jwt_token": {
        "pattern": r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        "severity": "medium",
        "description": "JSON Web Token (JWT)"
    },
    "database_url": {
        "pattern": r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@[^\s\"']+",
        "severity": "critical",
        "description": "Database Connection String with credentials"
    },
    "generic_api_key": {
        "pattern": r"(?i)(api_key|apikey|api-key|secret_key|secret-key)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?",
        "severity": "medium",
        "description": "Generic API Key assignment"
    },
    "generic_password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "severity": "medium",
        "description": "Hardcoded password"
    },
    "heroku_api_key": {
        "pattern": r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "high",
        "description": "Heroku API Key"
    },
    "npm_token": {
        "pattern": r"npm_[a-zA-Z0-9]{36}",
        "severity": "high",
        "description": "NPM Access Token"
    },
    "docker_hub": {
        "pattern": r"(?i)docker.{0,20}['\"][a-zA-Z0-9_\-]{30,}['\"]",
        "severity": "medium",
        "description": "Docker Hub Credential"
    },
    "mailgun_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "description": "Mailgun API Key"
    },
}

# Files whose names suggest they contain secrets
SENSITIVE_FILENAMES = [
    "*.env", ".env", ".env.local", ".env.production", ".env.staging", "*.pem", "*.key", "*.p12", "*.pfx",
    "credentials.json", "credentials.yml", "credentials.yaml",
    "secrets.json", "secrets.yml", "secrets.yaml",
    "config/database.yml", "database.yml",
    "*.keystore", "*.jks",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".netrc", ".pgpass",
    "terraform.tfvars", "*.tfvars",
    "*.env.development", "*.env.test"
]

# Extensions to skip (binary, generated, etc.)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".tar", ".pdf",
    ".pyc", ".class", ".so", ".dylib", ".dll", ".exe", ".bin"
}

ENTROPY_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


class SecretScanner:
    def __init__(self, config: SecretScanConfig):
        self.config = config
        self._compiled = {
            name: re.compile(p["pattern"])
            for name, p in SECRET_PATTERNS.items()
            if any(g in name or name in config.pattern_groups
                   for g in config.pattern_groups)
        }

    def scan(
        self,
        local_path: Optional[Path] = None,
        github_client=None,
        repo_name: Optional[str] = None,
        meta: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        findings = []

        if local_path and local_path.exists():
            findings.extend(self._scan_directory(local_path))
        elif github_client and repo_name:
            findings.extend(self._scan_via_api(github_client, repo_name))

        return findings

    def _scan_directory(self, root: Path) -> List[Dict]:
        findings = []
        for path in root.rglob("*"):
            if path.is_file() and not self._should_skip_path(path, root):
                findings.extend(self._scan_file(path, root))
        return findings

    def _scan_via_api(self, client, repo_name: str) -> List[Dict]:
        """Fallback: scan key files via GitHub API without cloning."""
        findings = []
        tree = client.get_file_tree(repo_name)
        target_files = [
            item["path"] for item in tree
            if item["type"] == "blob" and self._is_interesting_file(item["path"])
        ]
        # Limit API calls — warn if scan is capped
        if len(target_files) > 50:
            import warnings
            warnings.warn(
                f"API scan limited to 50 files — {len(target_files) - 50} files skipped. "
                f"Use --no-clone=False for a complete scan.",
                UserWarning
            )
        for file_path in target_files[:50]:
            content = client.get_file_content(repo_name, file_path)
            if content:
                file_findings = self._scan_content(content, file_path)
                findings.extend(file_findings)
        return findings

    def _scan_file(self, path: Path, root: Path) -> List[Dict]:
        rel = str(path.relative_to(root))

        # Check for sensitive filenames
        name_findings = self._check_filename(rel)

        try:
            content = path.read_text(errors="ignore")
        except Exception:
            return name_findings

        content_findings = self._scan_content(content, rel)
        return name_findings + content_findings

    def _scan_content(self, content: str, file_path: str) -> List[Dict]:
        findings = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            # Skip likely comments or test data
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")) and "BEGIN" not in stripped:
                continue

            # Regex pattern matching
            for pattern_name, regex in self._compiled.items():
                for match in regex.finditer(line):
                    matched_text = match.group(0)
                    if self._is_allowlisted(matched_text):
                        continue
                    meta = SECRET_PATTERNS.get(pattern_name, {})
                    findings.append({
                        "type": "secret",
                        "pattern": pattern_name,
                        "description": meta.get("description", pattern_name),
                        "severity": meta.get("severity", "medium"),
                        "file": file_path,
                        "line": lineno,
                        "match": self._redact(matched_text),
                        "context": self._redact(stripped[:120])
                    })

            # Entropy scan for high-entropy tokens not caught by regex
            for token in line.split():
                token = token.strip("'\"`,;")
                if len(token) >= 20 and all(c in ENTROPY_CHARS for c in token):
                    entropy = shannon_entropy(token)
                    if entropy >= self.config.entropy_threshold:
                        if not any(r.search(line) for r in self._compiled.values()):
                            findings.append({
                                "type": "secret",
                                "pattern": "high_entropy_string",
                                "description": f"High-entropy string (entropy={entropy:.2f})",
                                "severity": "low",
                                "file": file_path,
                                "line": lineno,
                                "match": self._redact(token),
                                "context": self._redact(stripped[:120])
                            })

        return findings

    def _check_filename(self, rel_path: str) -> List[Dict]:
        filename = Path(rel_path).name
        for pattern in SENSITIVE_FILENAMES:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(rel_path, pattern):
                return [{
                    "type": "secret",
                    "pattern": "sensitive_filename",
                    "description": "Sensitive file committed to repo",
                    "severity": "high",
                    "file": rel_path,
                    "line": None,
                    "match": filename,
                    "context": f"File matches sensitive pattern: {pattern}"
                }]
        return []

    # Directories that should never be scanned regardless of config
    ALWAYS_SKIP_DIRS = {
        ".git", "node_modules", ".tox", ".venv", "venv",
        ".mypy_cache", ".pytest_cache", "__pycache__",
        ".eggs", "*.egg-info", "dist", "build", ".idea", ".vscode"
    }

    def _should_skip_path(self, path: Path, root: Path) -> bool:
        rel = str(path.relative_to(root))
        parts = path.parts

        # Always skip internal tooling directories
        for part in parts:
            if part in self.ALWAYS_SKIP_DIRS or part.endswith(".egg-info"):
                return True

        for excluded in self.config.exclude_paths:
            if fnmatch.fnmatch(rel, excluded) or excluded in rel.split("/"):
                return True
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return True
        # Skip large files (> 1MB)
        try:
            if path.stat().st_size > 1_000_000:
                return True
        except Exception:
            pass
        return False

    def _is_interesting_file(self, file_path: str) -> bool:
        """For API-based scanning, which files are worth fetching?"""
        name = Path(file_path).name
        ext = Path(file_path).suffix.lower()
        if ext in SKIP_EXTENSIONS:
            return False
        # Interesting extensions
        if ext in {".py", ".js", ".ts", ".rb", ".go", ".java", ".php",
                   ".env", ".yml", ".yaml", ".json", ".toml", ".ini",
                   ".cfg", ".conf", ".sh", ".bash", ".zsh"}:
            return True
        # Interesting names
        for pattern in SENSITIVE_FILENAMES:
            if fnmatch.fnmatch(name, pattern):
                return True
        return False

    def _is_allowlisted(self, text: str) -> bool:
        for pattern in self.config.allowlist_patterns:
            if re.search(pattern, text):
                return True
        # Common test/example values
        false_positives = [
            "your_api_key", "YOUR_API_KEY", "example", "placeholder",
            "xxxxxxxx", "XXXXXXXX", "changeme", "TODO", "INSERT_HERE",
            "your_token_here",
        ]
        return any(fp.lower() in text.lower() for fp in false_positives)

    @staticmethod
    def _redact(text: str) -> str:
        """Partially redact secrets for safe display."""
        if len(text) <= 8:
            return "***"
        return text[:4] + "***" + text[-4:]
