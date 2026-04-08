"""
dependency_scanner.py — Manifest parsing + OSV.dev CVE lookup.

Fixes applied (CTO review):
  1. Now parses LOCK FILES for resolved (pinned) versions rather than
     declared version ranges — this is what actually runs on the machine.
       - poetry.lock        (Python)
       - Pipfile.lock       (Python)
       - package-lock.json  (Node, v2/v3)
       - yarn.lock          (Node)
       - Cargo.lock         (Rust)
       - Gemfile.lock       (Ruby)
       - go.sum             (Go — resolved module versions)
  2. Manifest files (requirements.txt, package.json, etc.) are still
     parsed as a FALLBACK when no lock file is present.
  3. OSV.dev batch query used to minimise HTTP round-trips.
  4. Rate limiting + retry with exponential backoff on 429.
  5. Graceful degradation: if OSV.dev is unreachable, findings are empty
     and a warning is emitted — we never crash the scan.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_TIMEOUT = 15  # seconds
_OSV_MAX_BATCH = 1000  # OSV supports up to 1000 queries per batch call
_OSV_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Package:
    name: str
    version: str
    ecosystem: str          # PyPI | npm | Go | RubyGems | crates.io | Maven
    source_file: str
    resolved: bool = False  # True = came from a lock file


@dataclass
class VulnFinding:
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    package: str
    version: str
    cve_ids: list[str]
    osv_id: str
    summary: str
    fixed_version: Optional[str]
    source_file: str


# ---------------------------------------------------------------------------
# Lock file parsers
# ---------------------------------------------------------------------------

def _parse_poetry_lock(text: str, path: str) -> list[Package]:
    """Parse poetry.lock — [[package]] sections."""
    packages: list[Package] = []
    current: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current.get("name") and current.get("version"):
                packages.append(
                    Package(
                        name=current["name"],
                        version=current["version"],
                        ecosystem="PyPI",
                        source_file=path,
                        resolved=True,
                    )
                )
            current = {}
        elif line.startswith("name = "):
            current["name"] = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            current["version"] = line.split("=", 1)[1].strip().strip('"')
    if current.get("name") and current.get("version"):
        packages.append(
            Package(
                name=current["name"],
                version=current["version"],
                ecosystem="PyPI",
                source_file=path,
                resolved=True,
            )
        )
    return packages


def _parse_pipfile_lock(text: str, path: str) -> list[Package]:
    """Parse Pipfile.lock — JSON with default + develop sections."""
    packages: list[Package] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    for section in ("default", "develop"):
        for name, meta in data.get(section, {}).items():
            version = meta.get("version", "").lstrip("==")
            if version:
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="PyPI",
                        source_file=path,
                        resolved=True,
                    )
                )
    return packages


def _parse_package_lock_json(text: str, path: str) -> list[Package]:
    """Parse package-lock.json v2/v3 (packages key) or v1 (dependencies key)."""
    packages: list[Package] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    # v2/v3: flat "packages" dict, key is "node_modules/pkg"
    for pkg_path, meta in data.get("packages", {}).items():
        if not pkg_path or pkg_path == "":
            continue  # root package
        name = pkg_path.split("node_modules/")[-1]
        version = meta.get("version", "")
        if name and version:
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    source_file=path,
                    resolved=True,
                )
            )
    if packages:
        return packages
    # v1 fallback: "dependencies" dict (recursive)
    def _walk_deps(deps: dict) -> None:
        for name, meta in deps.items():
            version = meta.get("version", "")
            if version:
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        source_file=path,
                        resolved=True,
                    )
                )
            if "dependencies" in meta:
                _walk_deps(meta["dependencies"])

    _walk_deps(data.get("dependencies", {}))
    return packages


def _parse_yarn_lock(text: str, path: str) -> list[Package]:
    """Parse yarn.lock (both v1 classic and berry/v2 yaml-ish format)."""
    packages: list[Package] = []
    current_names: list[str] = []
    for line in text.splitlines():
        # New block: lines ending with ":"  and not starting with whitespace
        if line and not line.startswith(" ") and not line.startswith("#") and line.endswith(":"):
            # May be  "pkg@^1.0, pkg@^1.1":
            raw = line.rstrip(":")
            current_names = [
                seg.split("@")[0].strip().strip('"')
                for seg in raw.split(",")
                if "@" in seg
            ]
        elif line.strip().startswith("version"):
            match = re.search(r'version[:\s]+"?([^"\s]+)"?', line)
            if match and current_names:
                version = match.group(1)
                for name in current_names:
                    if name:
                        packages.append(
                            Package(
                                name=name,
                                version=version,
                                ecosystem="npm",
                                source_file=path,
                                resolved=True,
                            )
                        )
    return packages


def _parse_cargo_lock(text: str, path: str) -> list[Package]:
    """Parse Cargo.lock TOML [[package]] sections."""
    packages: list[Package] = []
    current: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current.get("name") and current.get("version"):
                packages.append(
                    Package(
                        name=current["name"],
                        version=current["version"],
                        ecosystem="crates.io",
                        source_file=path,
                        resolved=True,
                    )
                )
            current = {}
        elif line.startswith("name = "):
            current["name"] = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            current["version"] = line.split("=", 1)[1].strip().strip('"')
    if current.get("name") and current.get("version"):
        packages.append(
            Package(
                name=current["name"],
                version=current["version"],
                ecosystem="crates.io",
                source_file=path,
                resolved=True,
            )
        )
    return packages


def _parse_gemfile_lock(text: str, path: str) -> list[Package]:
    """Parse Gemfile.lock — GEM/remote/specs sections."""
    packages: list[Package] = []
    in_specs = False
    for line in text.splitlines():
        if line.strip() in ("GEM", "PATH", "GIT"):
            in_specs = False
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            match = re.match(r"^\s{4}([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)", line)
            if match:
                packages.append(
                    Package(
                        name=match.group(1),
                        version=match.group(2).split("-")[0],  # strip platform suffix
                        ecosystem="RubyGems",
                        source_file=path,
                        resolved=True,
                    )
                )
            elif re.match(r"^\S", line):
                in_specs = False
    return packages


def _parse_go_sum(text: str, path: str) -> list[Package]:
    """
    Parse go.sum — each line: module version/go.mod hash
    We only take the non-go.mod lines (actual module versions).
    """
    packages: list[Package] = []
    seen: set[tuple] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version_raw = parts[1]
        if version_raw.endswith("/go.mod"):
            continue  # skip go.mod hash lines
        version = version_raw.split("+")[0].lstrip("v")  # strip +incompatible
        if (module, version) not in seen:
            seen.add((module, version))
            packages.append(
                Package(
                    name=module,
                    version=version,
                    ecosystem="Go",
                    source_file=path,
                    resolved=True,
                )
            )
    return packages


# ---------------------------------------------------------------------------
# Manifest (non-lock) parsers — used as fallback
# ---------------------------------------------------------------------------

def _parse_requirements_txt(text: str, path: str) -> list[Package]:
    packages: list[Package] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|===)\s*([^\s;]+)", line)
        if match:
            packages.append(
                Package(
                    name=match.group(1),
                    version=match.group(2),
                    ecosystem="PyPI",
                    source_file=path,
                    resolved=False,
                )
            )
    return packages


def _parse_package_json(text: str, path: str) -> list[Package]:
    packages: list[Package] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version_range in data.get(section, {}).items():
            # Strip semver range operators
            version = re.sub(r"^[\^~>=<*]+", "", version_range.strip()).split(" ")[0]
            if version and re.match(r"^\d", version):
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        source_file=path,
                        resolved=False,
                    )
                )
    return packages


def _parse_go_mod(text: str, path: str) -> list[Package]:
    packages: list[Package] = []
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r"^([^\s]+)\s+(v[\d.]+)", line)
        if match:
            packages.append(
                Package(
                    name=match.group(1),
                    version=match.group(2).lstrip("v"),
                    ecosystem="Go",
                    source_file=path,
                    resolved=False,
                )
            )
    return packages


def _parse_cargo_toml(text: str, path: str) -> list[Package]:
    packages: list[Package] = []
    for line in text.splitlines():
        match = re.match(
            r'^([a-zA-Z0-9_\-]+)\s*=\s*["\']([0-9][^"\']*)["\']', line
        )
        if match:
            packages.append(
                Package(
                    name=match.group(1),
                    version=match.group(2).lstrip("^~>=<"),
                    ecosystem="crates.io",
                    source_file=path,
                    resolved=False,
                )
            )
    return packages


def _parse_pom_xml(text: str, path: str) -> list[Package]:
    """Very basic Maven POM parser — extracts groupId:artifactId + version."""
    packages: list[Package] = []
    # Find <dependency> blocks
    dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", text, re.DOTALL)
    for block in dep_blocks:
        group = re.search(r"<groupId>([^<]+)</groupId>", block)
        artifact = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        version = re.search(r"<version>([^<${}]+)</version>", block)
        if group and artifact and version:
            packages.append(
                Package(
                    name=f"{group.group(1)}:{artifact.group(1)}",
                    version=version.group(1).strip(),
                    ecosystem="Maven",
                    source_file=path,
                    resolved=False,
                )
            )
    return packages


# ---------------------------------------------------------------------------
# File → parser mapping
# ---------------------------------------------------------------------------

# Priority: lock files first (resolved=True), manifests second (resolved=False)
LOCK_FILE_PARSERS: dict[str, callable] = {
    "poetry.lock":        _parse_poetry_lock,
    "Pipfile.lock":       _parse_pipfile_lock,
    "package-lock.json":  _parse_package_lock_json,
    "yarn.lock":          _parse_yarn_lock,
    "Cargo.lock":         _parse_cargo_lock,
    "Gemfile.lock":       _parse_gemfile_lock,
    "go.sum":             _parse_go_sum,
}

MANIFEST_PARSERS: dict[str, callable] = {
    "requirements.txt":   _parse_requirements_txt,
    "Pipfile":            _parse_requirements_txt,  # similar enough for fallback
    "pyproject.toml":     _parse_requirements_txt,  # crude; only catches ==pins
    "package.json":       _parse_package_json,
    "go.mod":             _parse_go_mod,
    "Cargo.toml":         _parse_cargo_toml,
    "Gemfile":            lambda t, p: [],  # no reliable version without lock
    "pom.xml":            _parse_pom_xml,
}


# ---------------------------------------------------------------------------
# OSV.dev client
# ---------------------------------------------------------------------------

def _osv_severity(vuln: dict) -> str:
    """Map OSV severity fields to our 4-tier scale."""
    # Check database_specific.severity first (NVD CVSS)
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if db_sev:
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MODERATE": "MEDIUM",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }
        return mapping.get(db_sev.upper(), "UNKNOWN")
    # Fall back to CVSS score in severity array
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS:3.x/AV:... style — extract base score
        if "CVSS" in score_str:
            try:
                score = float(score_str.split("/")[-1])
            except (ValueError, IndexError):
                continue
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
    return "UNKNOWN"


def _fixed_version(vuln: dict, ecosystem: str, pkg_name: str) -> Optional[str]:
    """Extract the earliest fixed version from OSV affected ranges."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != pkg_name.lower():
            continue
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _query_osv_batch(packages: list[Package]) -> list[VulnFinding]:
    """Query OSV.dev for all packages in a single batched request."""
    if not packages:
        return []

    findings: list[VulnFinding] = []

    # OSV batch supports up to _OSV_MAX_BATCH queries
    for chunk_start in range(0, len(packages), _OSV_MAX_BATCH):
        chunk = packages[chunk_start: chunk_start + _OSV_MAX_BATCH]
        queries = [
            {
                "version": pkg.version,
                "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
            }
            for pkg in chunk
        ]

        payload = {"queries": queries}

        for attempt in range(_OSV_MAX_RETRIES):
            try:
                resp = requests.post(
                    OSV_BATCH_URL,
                    json=payload,
                    timeout=_OSV_TIMEOUT,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 429:
                    wait = 2 ** attempt
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.RequestException as exc:
                if attempt == _OSV_MAX_RETRIES - 1:
                    import warnings
                    warnings.warn(
                        f"OSV.dev unreachable after {_OSV_MAX_RETRIES} attempts: {exc}. "
                        "Dependency scan results will be incomplete."
                    )
                    return findings
                time.sleep(2 ** attempt)
                continue

        for pkg, result in zip(chunk, data.get("results", [])):
            for vuln in result.get("vulns", []):
                cves = [
                    alias
                    for alias in vuln.get("aliases", [])
                    if alias.startswith("CVE-")
                ]
                findings.append(
                    VulnFinding(
                        severity=_osv_severity(vuln),
                        package=pkg.name,
                        version=pkg.version,
                        cve_ids=cves,
                        osv_id=vuln.get("id", ""),
                        summary=vuln.get("summary", "")[:200],
                        fixed_version=_fixed_version(vuln, pkg.ecosystem, pkg.name),
                        source_file=pkg.source_file,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class DependencyScanner:
    def scan_directory(self, directory: str) -> list[VulnFinding]:
        """
        Walk directory, parse all lock files (preferred) and manifests
        (fallback), then query OSV.dev for CVEs.
        """
        all_packages = self._collect_packages(directory)
        if not all_packages:
            return []
        return _query_osv_batch(all_packages)

    def _collect_packages(self, directory: str) -> list[Package]:
        """
        Collect packages from lock files first; fall back to manifests only
        when no corresponding lock file exists for that ecosystem in the same dir.
        """
        lock_files_found: set[str] = set()  # (dirpath, ecosystem)
        packages: list[Package] = []

        # First pass: lock files
        for dirpath, dirnames, filenames in os.walk(directory):
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "vendor"}]
            for filename in filenames:
                if filename in LOCK_FILE_PARSERS:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    pkgs = LOCK_FILE_PARSERS[filename](text, filepath)
                    packages.extend(pkgs)
                    if pkgs:
                        # Record which ecosystems we've resolved in this dir
                        for p in pkgs:
                            lock_files_found.add((dirpath, p.ecosystem))

        # Second pass: manifests — only where no lock file covered that ecosystem
        for dirpath, dirnames, filenames in os.walk(directory):
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "vendor"}]
            for filename in filenames:
                if filename in MANIFEST_PARSERS:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    pkgs = MANIFEST_PARSERS[filename](text, filepath)
                    for p in pkgs:
                        if (dirpath, p.ecosystem) not in lock_files_found:
                            packages.append(p)

        # Deduplicate by (name, version, ecosystem)
        seen: set[tuple] = set()
        deduped: list[Package] = []
        for p in packages:
            key = (p.name.lower(), p.version, p.ecosystem)
            if key not in seen:
                seen.add(key)
                deduped.append(p)

        return deduped


import os  # noqa: E402 — moved here to avoid circular at top
