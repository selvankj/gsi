"""
.gsiignore — project-level suppression file for gsi.

Syntax (one rule per line):
  # comment
  path/to/file.py              → ignore entire file
  path/to/file.py:42           → ignore specific line
  [pattern] description        → ignore by pattern name
  [secrets] test_*             → ignore secrets matching glob in filename

This module is imported by secret_scanner and pattern_scanner to
filter out known false positives before surfacing findings.
"""

import fnmatch
from pathlib import Path
from typing import Set, Tuple, Optional


class GsiIgnore:
    def __init__(self, root: Path):
        self.root = root
        self._ignored_files: Set[str] = set()
        self._ignored_lines: Set[Tuple[str, int]] = set()
        self._ignored_patterns: dict = {}   # pattern_name → list of globs
        self._load(root / ".gsiignore")

    def _load(self, path: Path):
        if not path.exists():
            return
        for raw_line in path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # [pattern_name] glob — e.g. [secrets] tests/*
            if line.startswith("["):
                end = line.find("]")
                if end != -1:
                    pname = line[1:end].strip()
                    glob  = line[end+1:].strip()
                    self._ignored_patterns.setdefault(pname, []).append(glob)
                continue

            # file.py:42
            if ":" in line:
                parts = line.rsplit(":", 1)
                try:
                    self._ignored_lines.add((parts[0], int(parts[1])))
                    continue
                except ValueError:
                    pass

            # bare path
            self._ignored_files.add(line)

    def should_suppress(self, file_path: str, line: Optional[int], pattern_name: str) -> bool:
        """Return True if this finding should be suppressed."""
        # Exact file match
        if file_path in self._ignored_files:
            return True
        # Glob file match
        for ignored in self._ignored_files:
            if fnmatch.fnmatch(file_path, ignored):
                return True
        # Line-level match
        if line and (file_path, line) in self._ignored_lines:
            return True
        # Pattern-level glob
        for glob in self._ignored_patterns.get(pattern_name, []):
            if fnmatch.fnmatch(file_path, glob):
                return True
        return False

    @classmethod
    def empty(cls) -> "GsiIgnore":
        """Return a no-op ignore instance (when no root is available)."""
        inst = cls.__new__(cls)
        inst._ignored_files = set()
        inst._ignored_lines = set()
        inst._ignored_patterns = {}
        return inst


EXAMPLE_GSIIGNORE = """\
# .gsiignore — gsi suppression rules
# Lines starting with # are comments.

# Ignore entire files
# tests/fixtures/fake_credentials.py
# docs/examples/aws_setup.md

# Ignore a specific line
# config/local.py:10

# Ignore a pattern category for matching files
# [secrets] tests/**
# [secrets] **/*_test.py
# [generic_api_key] docs/**

# Ignore all findings in a directory
# vendor/**
"""
