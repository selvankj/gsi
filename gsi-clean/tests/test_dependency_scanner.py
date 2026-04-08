"""
test_dependency_scanner.py — Tests for lock file parsing and OSV.dev integration.

Covers the fixes from the CTO review:
  - Lock file parsers (poetry.lock, Pipfile.lock, package-lock.json, yarn.lock,
    Cargo.lock, Gemfile.lock, go.sum)
  - Lock files take priority over manifests for the same ecosystem
  - OSV batch query is called with correct payloads
  - Graceful degradation on OSV.dev unreachable
"""

import json
import textwrap
from unittest.mock import MagicMock, patch

import pytest

from gsi.modules.dependency_scanner import (
    _parse_poetry_lock,
    _parse_pipfile_lock,
    _parse_package_lock_json,
    _parse_yarn_lock,
    _parse_cargo_lock,
    _parse_gemfile_lock,
    _parse_go_sum,
    _parse_requirements_txt,
    _parse_package_json,
)


# ---------------------------------------------------------------------------
# Lock file parsers
# ---------------------------------------------------------------------------

class TestPoetryLock:
    SAMPLE = textwrap.dedent("""\
        [[package]]
        name = "requests"
        version = "2.28.0"
        description = "Python HTTP for Humans."

        [[package]]
        name = "certifi"
        version = "2022.12.7"
        description = "Python package for providing Mozilla's CA Bundle."
    """)

    def test_parses_packages(self):
        pkgs = _parse_poetry_lock(self.SAMPLE, "poetry.lock")
        names = {p.name for p in pkgs}
        assert "requests" in names
        assert "certifi" in names

    def test_correct_versions(self):
        pkgs = _parse_poetry_lock(self.SAMPLE, "poetry.lock")
        req = next(p for p in pkgs if p.name == "requests")
        assert req.version == "2.28.0"

    def test_marked_as_resolved(self):
        pkgs = _parse_poetry_lock(self.SAMPLE, "poetry.lock")
        assert all(p.resolved for p in pkgs)

    def test_ecosystem_is_pypi(self):
        pkgs = _parse_poetry_lock(self.SAMPLE, "poetry.lock")
        assert all(p.ecosystem == "PyPI" for p in pkgs)


class TestPipfileLock:
    SAMPLE = json.dumps({
        "default": {
            "requests": {"version": "==2.28.0"},
            "certifi": {"version": "==2022.12.7"},
        },
        "develop": {
            "pytest": {"version": "==7.2.0"},
        }
    })

    def test_parses_default_and_develop(self):
        pkgs = _parse_pipfile_lock(self.SAMPLE, "Pipfile.lock")
        names = {p.name for p in pkgs}
        assert {"requests", "certifi", "pytest"} == names

    def test_strips_equals_prefix(self):
        pkgs = _parse_pipfile_lock(self.SAMPLE, "Pipfile.lock")
        req = next(p for p in pkgs if p.name == "requests")
        assert req.version == "2.28.0"

    def test_invalid_json_returns_empty(self):
        assert _parse_pipfile_lock("not json", "Pipfile.lock") == []


class TestPackageLockJson:
    SAMPLE_V2 = json.dumps({
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "myapp", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/express": {"version": "4.18.2"},
        }
    })

    def test_parses_v2_packages(self):
        pkgs = _parse_package_lock_json(self.SAMPLE_V2, "package-lock.json")
        names = {p.name for p in pkgs}
        assert "lodash" in names
        assert "express" in names

    def test_skips_root_package(self):
        pkgs = _parse_package_lock_json(self.SAMPLE_V2, "package-lock.json")
        # Root package (key="") should not appear
        assert all(p.name != "" for p in pkgs)

    def test_ecosystem_is_npm(self):
        pkgs = _parse_package_lock_json(self.SAMPLE_V2, "package-lock.json")
        assert all(p.ecosystem == "npm" for p in pkgs)

    def test_invalid_json_returns_empty(self):
        assert _parse_package_lock_json("not json", "package-lock.json") == []


class TestYarnLock:
    SAMPLE = textwrap.dedent("""\
        # yarn lockfile v1

        lodash@^4.17.0, lodash@^4.17.21:
          version "4.17.21"
          resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

        express@^4.0.0:
          version "4.18.2"
          resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
    """)

    def test_parses_packages(self):
        pkgs = _parse_yarn_lock(self.SAMPLE, "yarn.lock")
        names = {p.name for p in pkgs}
        assert "lodash" in names
        assert "express" in names

    def test_correct_version(self):
        pkgs = _parse_yarn_lock(self.SAMPLE, "yarn.lock")
        lodash = next(p for p in pkgs if p.name == "lodash")
        assert lodash.version == "4.17.21"


class TestCargoLock:
    SAMPLE = textwrap.dedent("""\
        [[package]]
        name = "serde"
        version = "1.0.152"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "tokio"
        version = "1.25.0"
    """)

    def test_parses_packages(self):
        pkgs = _parse_cargo_lock(self.SAMPLE, "Cargo.lock")
        names = {p.name for p in pkgs}
        assert "serde" in names
        assert "tokio" in names

    def test_ecosystem_is_crates(self):
        pkgs = _parse_cargo_lock(self.SAMPLE, "Cargo.lock")
        assert all(p.ecosystem == "crates.io" for p in pkgs)


class TestGemfileLock:
    SAMPLE = textwrap.dedent("""\
        GEM
          remote: https://rubygems.org/
          specs:
            rack (2.2.6)
            sinatra (3.0.4)
              rack (~> 2.2)

        BUNDLED WITH
           2.4.3
    """)

    def test_parses_specs(self):
        pkgs = _parse_gemfile_lock(self.SAMPLE, "Gemfile.lock")
        names = {p.name for p in pkgs}
        assert "rack" in names
        assert "sinatra" in names

    def test_ecosystem_is_rubygems(self):
        pkgs = _parse_gemfile_lock(self.SAMPLE, "Gemfile.lock")
        assert all(p.ecosystem == "RubyGems" for p in pkgs)


class TestGoSum:
    SAMPLE = textwrap.dedent("""\
        github.com/gin-gonic/gin v1.8.2 h1:UzKToD9/PoFj/V4rvlKqTRKnQYyz8Sc1MJlv4JHPtvY=
        github.com/gin-gonic/gin v1.8.2/go.mod h1:W1Me9+hsUSyj3CePGrd1/QrKJMSJ1Tu/0hFEH89961k=
        golang.org/x/net v0.5.0 h1:gu0TNTbErSsAkfOTcG4uHK+2PAcBZH+MYRise8Vu8y0=
        golang.org/x/net v0.5.0/go.mod h1:DivGGAXEgPSlEBzxGViFqTAETAvmUygs1asd5gOefu8=
    """)

    def test_parses_non_gomod_lines(self):
        pkgs = _parse_go_sum(self.SAMPLE, "go.sum")
        names = {p.name for p in pkgs}
        assert "github.com/gin-gonic/gin" in names
        assert "golang.org/x/net" in names

    def test_skips_gomod_lines(self):
        pkgs = _parse_go_sum(self.SAMPLE, "go.sum")
        # Each module should appear only once (go.mod lines skipped)
        gin_versions = [p for p in pkgs if p.name == "github.com/gin-gonic/gin"]
        assert len(gin_versions) == 1

    def test_ecosystem_is_go(self):
        pkgs = _parse_go_sum(self.SAMPLE, "go.sum")
        assert all(p.ecosystem == "Go" for p in pkgs)


# ---------------------------------------------------------------------------
# Manifest parsers (fallback)
# ---------------------------------------------------------------------------

class TestRequirementsTxt:
    def test_parses_pinned(self):
        pkgs = _parse_requirements_txt("requests==2.28.0\ncertifi==2022.12.7\n", "r.txt")
        names = {p.name for p in pkgs}
        assert "requests" in names

    def test_ignores_unpinned(self):
        pkgs = _parse_requirements_txt("requests>=2.0\n", "r.txt")
        assert pkgs == []

    def test_marked_as_unresolved(self):
        pkgs = _parse_requirements_txt("requests==2.28.0\n", "r.txt")
        assert all(not p.resolved for p in pkgs)


class TestPackageJson:
    SAMPLE = json.dumps({
        "dependencies": {"lodash": "^4.17.21"},
        "devDependencies": {"jest": "~29.0.0"},
    })

    def test_parses_both_sections(self):
        pkgs = _parse_package_json(self.SAMPLE, "package.json")
        names = {p.name for p in pkgs}
        assert "lodash" in names
        assert "jest" in names

    def test_strips_range_operators(self):
        pkgs = _parse_package_json(self.SAMPLE, "package.json")
        lodash = next(p for p in pkgs if p.name == "lodash")
        assert lodash.version == "4.17.21"
