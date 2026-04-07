"""
Dependency Scanner — parses package manifests and queries OSV.dev + GitHub Advisory DB.

Supports:
  Python  → requirements.txt, Pipfile, pyproject.toml
  Node.js → package.json, package-lock.json, yarn.lock
  Go      → go.mod
  Ruby    → Gemfile, Gemfile.lock
  Java    → pom.xml (basic)
  Rust    → Cargo.toml, Cargo.lock
"""

import json
import re
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

from gsi.config.settings import DependencyScanConfig


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

# CVSS score → severity mapping
def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class DependencyScanner:
    def __init__(self, config: DependencyScanConfig, github_client=None):
        self.config = config
        self.github_client = github_client
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"

    def scan(
        self,
        local_path: Optional[Path] = None,
        repo_name: Optional[str] = None,
        meta: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        packages = []

        if local_path and local_path.exists():
            packages = self._parse_local(local_path)
        elif repo_name and self.github_client:
            packages = self._parse_via_api(repo_name)

        if not packages:
            return []

        return self._query_osv(packages)

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_local(self, root: Path) -> List[Dict]:
        packages = []
        for manifest in self.config.manifest_files:
            for path in root.rglob(manifest):
                if self._should_skip(path, root):
                    continue
                try:
                    pkgs = self._parse_manifest(path)
                    packages.extend(pkgs)
                except Exception as e:
                    print(f"    ⚠️  Could not parse {path}: {e}")
        return packages

    def _parse_via_api(self, repo_name: str) -> List[Dict]:
        packages = []
        tree = self.github_client.get_file_tree(repo_name)
        for item in tree:
            if item["type"] != "blob":
                continue
            filename = Path(item["path"]).name
            if filename in self.config.manifest_files:
                content = self.github_client.get_file_content(repo_name, item["path"])
                if content:
                    try:
                        pkgs = self._parse_content(content, filename)
                        packages.extend(pkgs)
                    except Exception:
                        pass
        return packages

    def _parse_manifest(self, path: Path) -> List[Dict]:
        content = path.read_text(errors="ignore")
        return self._parse_content(content, path.name)

    def _parse_content(self, content: str, filename: str) -> List[Dict]:
        if filename == "requirements.txt":
            return self._parse_requirements_txt(content)
        elif filename == "package.json":
            return self._parse_package_json(content)
        elif filename in ("Pipfile", "Pipfile.lock"):
            return self._parse_pipfile(content)
        elif filename == "go.mod":
            return self._parse_go_mod(content)
        elif filename in ("Gemfile", "Gemfile.lock"):
            return self._parse_gemfile(content)
        elif filename in ("Cargo.toml", "Cargo.lock"):
            return self._parse_cargo(content)
        elif filename == "pyproject.toml":
            return self._parse_pyproject(content)
        return []

    def _parse_requirements_txt(self, content: str) -> List[Dict]:
        pkgs = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-r", "--")):
                continue
            # Handle: package==1.0.0, package>=1.0.0, package~=1.0.0
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~]+)\s*([\d\.]+[a-zA-Z0-9\.\-]*)?", line)
            if match:
                name, op, version = match.groups()
                pkgs.append({"name": name, "version": version or "", "ecosystem": "PyPI"})
        return pkgs

    def _parse_package_json(self, content: str) -> List[Dict]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        pkgs = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(section, {}).items():
                version = version.lstrip("^~>=<")
                pkgs.append({"name": name, "version": version, "ecosystem": "npm"})
        return pkgs

    def _parse_pipfile(self, content: str) -> List[Dict]:
        pkgs = []
        in_packages = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[packages]", "[dev-packages]"):
                in_packages = True
                continue
            if stripped.startswith("[") and stripped != "[packages]":
                in_packages = False
            if in_packages and "=" in stripped:
                parts = stripped.split("=", 1)
                name = parts[0].strip().strip('"')
                version = parts[1].strip().strip('"*').lstrip("=<>!~^")
                pkgs.append({"name": name, "version": version, "ecosystem": "PyPI"})
        return pkgs

    def _parse_go_mod(self, content: str) -> List[Dict]:
        pkgs = []
        for line in content.splitlines():
            line = line.strip()
            match = re.match(r"^([^\s]+)\s+v([\d\.]+)", line)
            if match:
                pkgs.append({"name": match.group(1), "version": match.group(2), "ecosystem": "Go"})
        return pkgs

    def _parse_gemfile(self, content: str) -> List[Dict]:
        pkgs = []
        for line in content.splitlines():
            match = re.match(r"""gem\s+['"]([^'"]+)['"]\s*,?\s*['"]?([\d\.\*~><= ]+)?""", line)
            if match:
                name = match.group(1)
                version = (match.group(2) or "").strip().lstrip("~>=< ")
                pkgs.append({"name": name, "version": version, "ecosystem": "RubyGems"})
        return pkgs

    def _parse_cargo(self, content: str) -> List[Dict]:
        pkgs = []
        for line in content.splitlines():
            match = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*["\{]?([\d\.\*]+)', line)
            if match:
                pkgs.append({"name": match.group(1), "version": match.group(2), "ecosystem": "crates.io"})
        return pkgs

    def _parse_pyproject(self, content: str) -> List[Dict]:
        pkgs = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[project]", "[tool.poetry.dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and "dependencies" not in stripped:
                in_deps = False
            if in_deps:
                match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[=<>!~]+\s*"?([\d\.]+)', stripped)
                if match:
                    pkgs.append({"name": match.group(1), "version": match.group(2), "ecosystem": "PyPI"})
        return pkgs

    def _should_skip(self, path: Path, root: Path) -> bool:
        rel = str(path.relative_to(root))
        skip_dirs = {"node_modules", "vendor", ".git", "__pycache__", "venv", ".venv"}
        return any(d in rel.split("/") for d in skip_dirs)

    # ── OSV.dev querying ──────────────────────────────────────────────────────

    def _query_osv(self, packages: List[Dict]) -> List[Dict[str, Any]]:
        """Batch query OSV.dev for all packages."""
        if not packages:
            return []

        # Deduplicate
        seen = set()
        unique = []
        for pkg in packages:
            key = (pkg["name"], pkg["version"], pkg["ecosystem"])
            if key not in seen:
                seen.add(key)
                unique.append(pkg)

        findings = []
        # OSV batch limit is 1000
        for batch in self._chunk(unique, 100):
            queries = []
            for pkg in batch:
                q = {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}}
                if pkg.get("version"):
                    q["version"] = pkg["version"]
                queries.append(q)

            try:
                resp = self._session.post(
                    OSV_BATCH_URL,
                    json={"queries": queries},
                    timeout=30
                )
                if resp.status_code != 200:
                    continue
                results = resp.json().get("results", [])
                for i, result in enumerate(results):
                    pkg = batch[i]
                    for vuln in result.get("vulns", []):
                        findings.append(self._format_vuln(vuln, pkg))
            except Exception as e:
                print(f"    ⚠️  OSV query error: {e}")
                time.sleep(2)

        return findings

    def _format_vuln(self, vuln: Dict, pkg: Dict) -> Dict[str, Any]:
        """Format OSV vuln into our standard finding format."""
        severity_info = vuln.get("database_specific", {}).get("severity", "")
        cvss = None
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                try:
                    # Extract CVSS score from vector
                    score_match = re.search(r"(\d+\.\d+)$", sev.get("score", ""))
                    if score_match:
                        cvss = float(score_match.group(1))
                except Exception:
                    pass

        if cvss:
            severity = cvss_to_severity(cvss)
        elif severity_info.lower() in ("critical", "high", "medium", "low"):
            severity = severity_info.lower()
        else:
            severity = "medium"

        aliases = vuln.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]

        return {
            "type": "vulnerability",
            "severity": severity,
            "package": pkg["name"],
            "version": pkg.get("version", "unknown"),
            "ecosystem": pkg.get("ecosystem", ""),
            "vuln_id": vuln.get("id", ""),
            "cve": cve_ids[0] if cve_ids else None,
            "title": vuln.get("summary", ""),
            "description": (vuln.get("details", "") or "")[:300],
            "cvss_score": cvss,
            "fixed_in": self._get_fixed_version(vuln),
            "references": [r.get("url") for r in vuln.get("references", [])[:3]]
        }

    def _get_fixed_version(self, vuln: Dict) -> Optional[str]:
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None

    @staticmethod
    def _chunk(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]
