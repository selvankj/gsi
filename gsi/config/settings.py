"""
Configuration and settings management.
Supports YAML config file + environment variables + CLI args.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path


@dataclass
class SecretScanConfig:
    enabled: bool = True
    # Regex pattern groups to enable
    pattern_groups: List[str] = field(default_factory=lambda: [
        "aws", "gcp", "azure", "github", "slack", "stripe",
        "twilio", "sendgrid", "generic_api_key", "private_key",
        "database_url", "jwt", "oauth"
    ])
    # Files/dirs to skip
    exclude_paths: List[str] = field(default_factory=lambda: [
        ".git", "node_modules", "vendor", "__pycache__", "*.min.js",
        "*.lock", "package-lock.json", "yarn.lock"
    ])
    # Known false-positive patterns to suppress
    allowlist_patterns: List[str] = field(default_factory=list)
    entropy_threshold: float = 3.5  # Shannon entropy for generic key detection
    scan_git_history: bool = False   # Whether to scan git commit history


@dataclass
class DependencyScanConfig:
    enabled: bool = True
    # Package manifests to scan
    manifest_files: List[str] = field(default_factory=lambda: [
        "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
        "package.json", "package-lock.json", "yarn.lock",
        "go.mod", "go.sum",
        "Gemfile", "Gemfile.lock",
        "pom.xml", "build.gradle",
        "Cargo.toml", "Cargo.lock",
        "composer.json", "composer.lock"
    ])
    use_osv: bool = True       # Query OSV.dev for CVEs
    use_github_advisory: bool = True  # Query GitHub Advisory DB
    min_cvss_score: float = 0.0


@dataclass
class RiskScoringConfig:
    enabled: bool = True
    weights: Dict[str, float] = field(default_factory=lambda: {
        "is_archived": 0.15,
        "no_recent_commits": 0.15,
        "no_security_policy": 0.10,
        "no_branch_protection": 0.10,
        "public_with_secrets": 0.25,
        "high_cve_count": 0.15,
        "no_dependabot": 0.10,
    })
    stale_days_threshold: int = 180  # Days since last commit to flag as stale


@dataclass
class PatternScanConfig:
    enabled: bool = True
    # Code anti-patterns to detect
    checks: List[str] = field(default_factory=lambda: [
        "hardcoded_credentials",
        "insecure_http",
        "sql_injection_risk",
        "command_injection_risk",
        "weak_crypto",
        "debug_code_left",
        "todo_fixme_security",
        "eval_usage",
        "insecure_deserialization",
        "path_traversal_risk",
        "xxe_risk",
        "ssrf_risk",
    ])
    exclude_paths: List[str] = field(default_factory=lambda: [
        ".git", "node_modules", "vendor", "__pycache__", "tests", "test"
    ])


@dataclass
class Settings:
    github_token: Optional[str] = None
    clone_repos: bool = True
    clone_dir: str = "/tmp/ghsec_clones"
    max_repo_size_mb: int = 500
    request_timeout: int = 30
    max_workers: int = 4

    secrets: SecretScanConfig = field(default_factory=SecretScanConfig)
    deps: DependencyScanConfig = field(default_factory=DependencyScanConfig)
    risk: RiskScoringConfig = field(default_factory=RiskScoringConfig)
    patterns: PatternScanConfig = field(default_factory=PatternScanConfig)

    @classmethod
    def load(cls, config_path: Optional[str], args=None) -> "Settings":
        settings = cls()

        # 1. Load from YAML file if provided
        if config_path:
            path = Path(config_path)
            if path.exists():
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                settings._apply_dict(data)

        # 2. Environment variables override file
        if token := os.environ.get("GITHUB_TOKEN"):
            settings.github_token = token

        # 3. CLI args override everything
        if args:
            if getattr(args, "token", None):
                settings.github_token = args.token
            if getattr(args, "no_clone", False):
                settings.clone_repos = False

        return settings

    def _apply_dict(self, data: Dict[str, Any]):
        for key, value in data.items():
            if hasattr(self, key) and not isinstance(value, dict):
                setattr(self, key, value)
            elif key == "secrets" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.secrets, k):
                        setattr(self.secrets, k, v)
            elif key == "deps" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.deps, k):
                        setattr(self.deps, k, v)
            elif key == "risk" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.risk, k):
                        setattr(self.risk, k, v)
            elif key == "patterns" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.patterns, k):
                        setattr(self.patterns, k, v)

    def validate(self):
        """Raise if required settings are missing."""
        errors = []
        if not self.github_token:
            errors.append("GitHub token is required (--token or GITHUB_TOKEN env var)")
        if errors:
            raise ValueError("\n".join(errors))
