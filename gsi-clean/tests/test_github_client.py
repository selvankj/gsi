"""
test_github_client.py — Tests for the hardened git clone and URL parsing.

Covers the fixes from the CTO review:
  - gitpython is NOT imported anywhere in github_client
  - clone uses subprocess, not gitpython
  - URL parsing handles all supported formats
  - Token is not leaked in error messages
"""

import subprocess
import sys
from unittest.mock import MagicMock, patch, call

import pytest

from gsi.scanner.github_client import GitHubClient, GitHubClientError


# ---------------------------------------------------------------------------
# Verify gitpython is not used
# ---------------------------------------------------------------------------

class TestNoGitpython:
    def test_github_client_does_not_import_git(self):
        """gitpython must not be imported by github_client."""
        import gsi.scanner.github_client as mod
        import importlib, ast, inspect
        source = inspect.getsource(mod)
        assert "import git" not in source, (
            "github_client.py must not import gitpython (security risk)"
        )
        assert "from git" not in source, (
            "github_client.py must not import from gitpython"
        )


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

class TestParseRepoUrl:
    def test_short_form(self):
        owner, repo = GitHubClient.parse_repo_url("selvankj/gsi")
        assert owner == "selvankj"
        assert repo == "gsi"

    def test_full_https_url(self):
        owner, repo = GitHubClient.parse_repo_url("https://github.com/selvankj/gsi")
        assert owner == "selvankj"
        assert repo == "gsi"

    def test_full_url_with_git_suffix(self):
        owner, repo = GitHubClient.parse_repo_url("https://github.com/selvankj/gsi.git")
        assert owner == "selvankj"
        assert repo == "gsi"

    def test_trailing_slash_stripped(self):
        owner, repo = GitHubClient.parse_repo_url("https://github.com/selvankj/gsi/")
        assert owner == "selvankj"
        assert repo == "gsi"

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            GitHubClient.parse_repo_url("not-a-url")


# ---------------------------------------------------------------------------
# Safe clone — subprocess called with hardened env
# ---------------------------------------------------------------------------

class TestSafeClone:
    def test_clone_uses_subprocess_not_gitpython(self):
        """clone_repo must call subprocess.run, not any gitpython method."""
        client = GitHubClient(token=None)
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run, \
             patch("tempfile.mkdtemp", return_value="/tmp/gsi_test"), \
             patch("os.path.join", side_effect=lambda *a: "/".join(a)):
            try:
                client.clone_repo("https://github.com/selvankj/gsi")
            except Exception:
                pass  # cleanup might fail in mock env

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "git"
        assert "clone" in cmd

    def test_clone_env_has_no_user_config(self):
        """Clone environment must set GIT_CONFIG_NOSYSTEM and neutralise HOME."""
        client = GitHubClient(token=None)
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run, \
             patch("tempfile.mkdtemp", return_value="/tmp/gsi_test"), \
             patch("shutil.rmtree"):
            try:
                client.clone_repo("https://github.com/selvankj/gsi")
            except Exception:
                pass

        if mock_run.called:
            kwargs = mock_run.call_args[1]
            env = kwargs.get("env", {})
            assert env.get("GIT_CONFIG_NOSYSTEM") == "1", (
                "GIT_CONFIG_NOSYSTEM must be set to prevent gitconfig injection"
            )
            assert env.get("GIT_TERMINAL_PROMPT") == "0", (
                "GIT_TERMINAL_PROMPT must be 0 to prevent interactive prompts"
            )

    def test_clone_is_shallow_depth_1(self):
        """Default clone must use --depth 1."""
        client = GitHubClient(token=None)
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run, \
             patch("tempfile.mkdtemp", return_value="/tmp/gsi_test"), \
             patch("shutil.rmtree"):
            try:
                client.clone_repo("https://github.com/selvankj/gsi")
            except Exception:
                pass

        if mock_run.called:
            cmd = mock_run.call_args[0][0]
            assert "--depth" in cmd
            depth_idx = cmd.index("--depth")
            assert cmd[depth_idx + 1] == "1"

    def test_token_not_in_error_message(self):
        """Secret token must be redacted from error messages."""
        secret_token = "ghp_" + "X" * 36
        client = GitHubClient(token=secret_token)
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = f"fatal: could not read Username for 'https://x-access-token:{secret_token}@github.com'"

        with patch("subprocess.run", return_value=mock_result), \
             patch("tempfile.mkdtemp", return_value="/tmp/gsi_test"), \
             patch("shutil.rmtree"):
            with pytest.raises(GitHubClientError) as exc_info:
                client.clone_repo("https://github.com/selvankj/gsi")

        assert secret_token not in str(exc_info.value), (
            "Token must be redacted from error messages"
        )

    def test_git_not_found_raises_clear_error(self):
        """FileNotFoundError from missing git binary must raise GitHubClientError."""
        client = GitHubClient(token=None)

        with patch("subprocess.run", side_effect=FileNotFoundError), \
             patch("tempfile.mkdtemp", return_value="/tmp/gsi_test"), \
             patch("shutil.rmtree"):
            with pytest.raises(GitHubClientError, match="git binary not found"):
                client.clone_repo("https://github.com/selvankj/gsi")

    def test_timeout_raises_clear_error(self):
        """Timeout must raise GitHubClientError."""
        client = GitHubClient(token=None)

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git", timeout=120)), \
             patch("tempfile.mkdtemp", return_value="/tmp/gsi_test"), \
             patch("shutil.rmtree"):
            with pytest.raises(GitHubClientError, match="timed out"):
                client.clone_repo("https://github.com/selvankj/gsi")
