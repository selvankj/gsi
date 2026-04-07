"""
GitHub API client — wraps PyGitHub with rate-limit awareness and
convenience methods for the scanner.
"""

import os
import time
import subprocess
import shutil
from pathlib import Path
from typing import Iterator, Optional, List, Dict, Any

try:
    from github import Github
    PYGITHUB_AVAILABLE = True
except ImportError:
    PYGITHUB_AVAILABLE = False

import requests


class GitHubClient:
    def __init__(self, token: Optional[str] = None, clone_dir: str = "/tmp/ghsec_clones"):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.clone_dir = Path(clone_dir)
        self.clone_dir.mkdir(parents=True, exist_ok=True)
        self._gh = None
        self._session = None

        if self.token and PYGITHUB_AVAILABLE:
            self._gh = Github(self.token, per_page=100)

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            if self.token:
                self._session.headers["Authorization"] = f"token {self.token}"
            self._session.headers["Accept"] = "application/vnd.github.v3+json"
        return self._session

    # ── Repo metadata ─────────────────────────────────────────────────────────

    def get_repo_meta(self, full_name: str) -> Dict[str, Any]:
        """Return repo metadata dict (works without PyGitHub)."""
        url = f"https://api.github.com/repos/{full_name}"
        resp = self.session.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_org_repos(self, org: str) -> Iterator[Dict[str, Any]]:
        """Yield all repos for an org."""
        page = 1
        while True:
            url = f"https://api.github.com/orgs/{org}/repos"
            resp = self.session.get(url, params={"per_page": 100, "page": page}, timeout=30)
            resp.raise_for_status()
            repos = resp.json()
            if not repos:
                break
            yield from repos
            page += 1

    def get_branch_protection(self, full_name: str, branch: str = "main") -> Optional[Dict]:
        """Return branch protection rules or None if not protected."""
        for b in [branch, "master"]:
            url = f"https://api.github.com/repos/{full_name}/branches/{b}/protection"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                return resp.json()
        return None

    def get_security_advisories(self, full_name: str) -> List[Dict]:
        """Return GitHub security advisories for a repo."""
        url = f"https://api.github.com/repos/{full_name}/security-advisories"
        resp = self.session.get(url, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        return []

    def get_dependabot_alerts(self, full_name: str) -> List[Dict]:
        """Return Dependabot vulnerability alerts."""
        url = f"https://api.github.com/repos/{full_name}/dependabot/alerts"
        resp = self.session.get(url, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        return []

    def has_security_policy(self, full_name: str) -> bool:
        """Check if repo has SECURITY.md."""
        for path in ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]:
            url = f"https://api.github.com/repos/{full_name}/contents/{path}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                return True
        return False

    def get_file_tree(self, full_name: str, branch: str = "HEAD") -> List[Dict]:
        """Return flat file tree via Git Trees API."""
        url = f"https://api.github.com/repos/{full_name}/git/trees/{branch}?recursive=1"
        resp = self.session.get(url, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("tree", [])
        return []

    def get_file_content(self, full_name: str, path: str) -> Optional[str]:
        """Fetch raw file content from GitHub."""
        owner, repo = full_name.split("/", 1)
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
        resp = self.session.get(url, timeout=15)
        if resp.status_code == 200:
            try:
                return resp.text
            except Exception:
                return None
        return None

    # ── Local clone ────────────────────────────────────────────────────────────

    def clone_repo(self, full_name: str) -> Optional[Path]:
        """Clone a repo locally; return the path or None on failure."""
        dest = self.clone_dir / full_name.replace("/", "_")
        if dest.exists():
            # Pull latest
            try:
                subprocess.run(["git", "-C", str(dest), "pull", "--quiet"],
                               capture_output=True, timeout=120)
                return dest
            except Exception:
                shutil.rmtree(dest, ignore_errors=True)

        url = f"https://github.com/{full_name}.git"
        if self.token:
            url = f"https://{self.token}@github.com/{full_name}.git"

        try:
            subprocess.run(
                ["git", "clone", "--depth=1", "--quiet", url, str(dest)],
                capture_output=True, timeout=300, check=True
            )
            return dest
        except subprocess.CalledProcessError as e:
            print(f"  ⚠️  Clone failed for {full_name}: {e.stderr.decode()[:200]}")
            return None

    def cleanup_clone(self, full_name: str):
        dest = self.clone_dir / full_name.replace("/", "_")
        shutil.rmtree(dest, ignore_errors=True)

    # ── Rate limit helpers ─────────────────────────────────────────────────────

    def check_rate_limit(self) -> Dict[str, Any]:
        resp = self.session.get("https://api.github.com/rate_limit", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("rate", {})
        return {}

    def wait_if_rate_limited(self):
        rate = self.check_rate_limit()
        if rate.get("remaining", 1) < 10:
            reset = rate.get("reset", time.time() + 60)
            wait = max(0, reset - time.time()) + 5
            print(f"  ⏳ Rate limited. Waiting {wait:.0f}s...")
            time.sleep(wait)
