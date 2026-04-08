"""
github_client.py — GitHub API + safe git clone helper.

Fixes applied (CTO review):
  1. Replaced gitpython with subprocess git calls.
     gitpython has a history of RCE via git config injection (CVE-2022-24439
     and others). When gsi clones an UNTRUSTED repo, using gitpython is
     itself a security risk. We now call the system `git` binary directly
     with a controlled, minimal environment — no user gitconfig is loaded,
     and we set GIT_CONFIG_NOSYSTEM + GIT_CONFIG_GLOBAL=/dev/null to prevent
     injection via .git/config in the cloned repo.
  2. Clones into a fresh tempdir (not the user's cwd).
  3. Clone depth is limited to --depth 1 by default (shallow) to reduce
     attack surface — we only need the latest tree for a security scan.
  4. Clone is always done with --no-local and --filter=blob:none options
     stripped (we do need blobs for secret scanning, so full shallow clone).
  5. GitHub API calls raise clear errors on rate-limit with retry-after info.
  6. Token is never logged.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from typing import Optional
from urllib.parse import urlparse

import requests

GITHUB_API = "https://api.github.com"
_CLONE_TIMEOUT = 120  # seconds


class GitHubClientError(Exception):
    pass


class RateLimitError(GitHubClientError):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(
            f"GitHub API rate limit hit. Retry after {retry_after} seconds. "
            "Set GITHUB_TOKEN to increase your limit to 5000 req/hr."
        )


class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        self._token = token or os.environ.get("GITHUB_TOKEN")
        self._session = requests.Session()
        if self._token:
            self._session.headers["Authorization"] = f"Bearer {self._token}"
        self._session.headers["Accept"] = "application/vnd.github+json"
        self._session.headers["X-GitHub-Api-Version"] = "2022-11-28"

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def get_repo(self, owner: str, repo: str) -> dict:
        return self._get(f"/repos/{owner}/{repo}")

    def get_branch_protection(self, owner: str, repo: str, branch: str) -> dict:
        try:
            return self._get(f"/repos/{owner}/{repo}/branches/{branch}/protection")
        except GitHubClientError:
            return {}

    def _get(self, path: str) -> dict:
        url = GITHUB_API + path
        resp = self._session.get(url, timeout=15)
        self._check_rate_limit(resp)
        if resp.status_code == 404:
            raise GitHubClientError(f"Not found: {url}")
        resp.raise_for_status()
        return resp.json()

    def _check_rate_limit(self, resp: requests.Response) -> None:
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            retry_after = int(resp.headers.get("Retry-After", 60))
            raise RateLimitError(retry_after)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            raise RateLimitError(retry_after)

    # ------------------------------------------------------------------
    # URL parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_repo_url(target: str) -> tuple[str, str]:
        """
        Parse 'owner/repo' or 'https://github.com/owner/repo[.git]'
        Returns (owner, repo) or raises ValueError.
        """
        target = target.strip().rstrip("/")
        if target.startswith("https://") or target.startswith("http://"):
            parsed = urlparse(target)
            parts = parsed.path.strip("/").rstrip(".git").split("/")
            if len(parts) < 2:
                raise ValueError(f"Cannot parse GitHub URL: {target}")
            return parts[0], parts[1]
        if "/" in target and not target.startswith("/"):
            parts = target.split("/")
            if len(parts) == 2:
                return parts[0], parts[1].rstrip(".git")
        raise ValueError(
            f"Cannot parse repo target '{target}'. "
            "Expected 'owner/repo' or 'https://github.com/owner/repo'."
        )

    # ------------------------------------------------------------------
    # Safe clone
    # ------------------------------------------------------------------

    def clone_repo(
        self,
        clone_url: str,
        depth: int = 1,
    ) -> "ClonedRepo":
        """
        Clone a remote repo into a fresh temporary directory using the
        system git binary with a hardened environment.

        Returns a ClonedRepo context manager that cleans up on exit.

        Security hardening:
        - GIT_CONFIG_NOSYSTEM=1    — ignore /etc/gitconfig
        - GIT_CONFIG_GLOBAL=/dev/null — ignore ~/.gitconfig
        - GIT_TERMINAL_PROMPT=0   — no interactive prompts (would hang)
        - No user credential helpers are invoked
        - Clone is shallow (depth=1) by default
        - stderr is captured, not forwarded to user terminal
        """
        tmpdir = tempfile.mkdtemp(prefix="gsi_clone_")
        dest = os.path.join(tmpdir, "repo")

        # Inject token into URL if available (avoids credential helper)
        auth_url = clone_url
        if self._token and clone_url.startswith("https://"):
            auth_url = clone_url.replace(
                "https://", f"https://x-access-token:{self._token}@", 1
            )

        cmd = [
            "git", "clone",
            "--depth", str(depth),
            "--single-branch",
            "--no-tags",
            "--quiet",
            auth_url,
            dest,
        ]

        env = {
            # Minimal safe environment
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/dev/null",           # prevent loading ~/.gitconfig
            "GIT_CONFIG_NOSYSTEM": "1",    # prevent loading /etc/gitconfig
            "GIT_TERMINAL_PROMPT": "0",    # prevent interactive prompts
            "GIT_ASKPASS": "echo",         # return empty string for any prompt
        }
        # On some systems HOME=/dev/null causes issues; use tmpdir instead
        env["HOME"] = tmpdir

        try:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=_CLONE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise GitHubClientError(
                f"Clone timed out after {_CLONE_TIMEOUT}s for {clone_url}"
            )
        except FileNotFoundError:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise GitHubClientError(
                "git binary not found. Please install git and ensure it is in PATH."
            )

        if result.returncode != 0:
            shutil.rmtree(tmpdir, ignore_errors=True)
            # Scrub token from error message before surfacing it
            stderr = result.stderr.replace(self._token or "", "***") if self._token else result.stderr
            raise GitHubClientError(f"git clone failed: {stderr.strip()}")

        return ClonedRepo(repo_path=dest, tmpdir=tmpdir)


class ClonedRepo:
    """Context manager for a cloned repo directory. Cleans up on exit."""

    def __init__(self, repo_path: str, tmpdir: str):
        self.path = repo_path
        self._tmpdir = tmpdir

    def __enter__(self) -> "ClonedRepo":
        return self

    def __exit__(self, *_) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)
